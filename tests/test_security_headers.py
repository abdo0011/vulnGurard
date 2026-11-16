import json
import re
from types import SimpleNamespace

import pytest

from scanner.crawler import Page
from scanner.detectors import get_detectors
from scanner.detectors.security_headers import (SecurityHeadersDetector, classify_frame_ancestors, csp_script_weaknesses,
                                                effective_referrer_policy, parse_csp, parse_hsts_max_age,
                                                scan_meta)
from scanner.engine import ScanEngine
from scanner.http_client import HttpResponse, ScanHTTPClient
from scanner.models import SEVERITIES
from scanner.result_processor import dedupe
from conftest import page as html_page

GOOD = {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=()',
}


def resp(url='https://a.test/', status=200, headers=None, body='<html><head></head></html>',
         content_type='text/html; charset=utf-8', cls=HttpResponse):
    hdrs = [] if content_type is None else [('Content-Type', content_type)]
    hdrs += list((headers or {}).items()) if isinstance(headers or {}, dict) else list(headers)
    return cls(url=url, method='GET', status=status, reason='', headers=hdrs,
               body=body.encode() if isinstance(body, str) else body, truncated=False,
               ip='93.184.216.34', scheme=url.split(':')[0])


def detect(*responses):
    pages = [Page(r.url, 0, r) for r in responses]
    return SecurityHeadersDetector().run(SimpleNamespace(pages=pages, client=None, target=None, config=None))


def rules(findings):
    return {f.extra['rule'] for f in findings}


def only(findings, rule):
    match = [f for f in findings if f.extra['rule'] == rule]
    assert len(match) == 1, f'{rule}: {len(match)} findings in {rules(findings)}'
    return match[0]


# ---------------------------------------------------------------- header present and correct
def test_fully_hardened_https_page_has_no_findings():
    assert detect(resp(headers=GOOD)) == []


def test_header_presence_alone_is_never_a_finding():
    """Odd but acceptable values must not be reported just because the header exists."""
    headers = dict(GOOD, **{'X-Frame-Options': 'sameorigin', 'X-Content-Type-Options': 'NoSniff',
                            'Referrer-Policy': 'no-referrer, strict-origin'})
    headers.pop('Content-Security-Policy')
    headers['Content-Security-Policy'] = "default-src 'self'"
    assert detect(resp(headers=headers)) == []


# ---------------------------------------------------------------- header missing
def test_everything_missing_on_https_document():
    f = detect(resp())
    assert rules(f) == {'HDR-CSP-MISSING', 'HDR-HSTS-MISSING', 'HDR-XCTO-MISSING', 'HDR-XFO-MISSING',
                        'HDR-REFERRER-MISSING', 'HDR-PERMISSIONS-MISSING'}
    sev = {x.extra['rule']: x.severity for x in f}
    assert sev == {'HDR-CSP-MISSING': 'Medium', 'HDR-HSTS-MISSING': 'Low', 'HDR-XCTO-MISSING': 'Low',
                   'HDR-XFO-MISSING': 'Low', 'HDR-REFERRER-MISSING': 'Informational',
                   'HDR-PERMISSIONS-MISSING': 'Informational'}
    assert not any(s in ('Critical', 'High') for s in sev.values())     # missing headers are never High
    for x in f:
        assert x.confidence == 'Confirmed' and x.category == 'security_headers'
        assert x.affected_urls == ['https://a.test/'] and 'HTTP 200' in x.evidence
        assert x.remediation and x.reference.startswith('OWASP') and x.detection_method.startswith('Passive')
        assert x.impact and x.description and x.extra['severity_explanation']


def test_hsts_only_judged_over_https():
    assert 'HDR-HSTS-MISSING' not in rules(detect(resp('http://a.test/')))
    assert 'HDR-HSTS-MISSING' in rules(detect(resp('https://a.test/')))


def test_missing_headers_are_deduplicated_across_pages():
    f = detect(resp('https://a.test/'), resp('https://a.test/x'), resp('https://a.test/y'))
    csp = only(f, 'HDR-CSP-MISSING')
    assert csp.affected_urls == ['https://a.test/', 'https://a.test/x', 'https://a.test/y']
    assert '3 pages are affected in total.' in csp.evidence and len(f) == 6


def test_pages_with_gaps_and_pages_without_are_separated():
    f = detect(resp('https://a.test/ok', headers=GOOD), resp('https://a.test/bad'))
    assert only(f, 'HDR-CSP-MISSING').affected_urls == ['https://a.test/bad']


# ---------------------------------------------------------------- weak configurations: CSP
@pytest.mark.parametrize('policy,weak', [
    ("script-src 'self' 'unsafe-inline'", True),
    ("default-src 'self' 'unsafe-inline'", True),                       # default-src applies to scripts
    ("script-src 'self' 'unsafe-eval'", True),
    ("script-src *", True),
    ("script-src 'self' https:", True),
    ("script-src data:", True),
    ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", False),        # nonce makes browsers ignore unsafe-inline
    ("script-src 'unsafe-inline' 'sha256-AAAA'", False),
    ("script-src 'strict-dynamic' 'unsafe-inline' https: *", True),       # strict-dynamic alone is not enough
    ("script-src 'nonce-abc123' 'strict-dynamic' 'unsafe-inline' https: *", False),  # documented compatible pattern
    ("script-src 'sha256-AAAA=' 'strict-dynamic' https:", False),
    ("script-src 'self'; style-src 'unsafe-inline'", False),            # unsafe-inline only for styles
    ("default-src 'self'; script-src 'self'", False),
    ("frame-ancestors 'none'", False),                                  # no script scope: not called weak
    ("default-src 'none'", False),
])
def test_csp_weakness_rules(policy, weak):
    (parsed,) = parse_csp([policy])
    assert bool(csp_script_weaknesses(parsed)) is weak


def test_weak_csp_reported_with_reasons_and_nonce_redacted():
    f = detect(resp(headers={**GOOD, 'Content-Security-Policy':
                             "script-src 'nonce-SUPERSECRETNONCE' 'unsafe-eval' *"}))
    x = only(f, 'HDR-CSP-UNSAFE')
    assert "'unsafe-eval'" in x.evidence and 'wildcard' in x.evidence
    assert 'SUPERSECRETNONCE' not in x.evidence and "'nonce-[redacted]'" in x.evidence
    assert x.severity == 'Low'


def test_multiple_policies_are_weak_only_if_every_policy_is_weak():
    strict = {'Content-Security-Policy': "script-src 'self'"}
    weak_and_strict = [('Content-Security-Policy', "script-src 'unsafe-inline'"),
                       ('Content-Security-Policy', "script-src 'self'")]
    assert 'HDR-CSP-UNSAFE' not in rules(detect(resp(headers=weak_and_strict)))
    assert 'HDR-CSP-UNSAFE' not in rules(detect(resp(headers={'Content-Security-Policy':
                                                              "script-src 'unsafe-inline', script-src 'self'"})))
    assert 'HDR-CSP-UNSAFE' in rules(detect(resp(headers={'Content-Security-Policy':
                                                          "script-src 'unsafe-inline', script-src *"})))
    assert 'HDR-CSP-UNSAFE' not in rules(detect(resp(headers=strict)))


def test_report_only_policy():
    ro = {'Content-Security-Policy-Report-Only': "default-src 'self'"}
    assert 'HDR-CSP-REPORT-ONLY' in rules(detect(resp(headers=ro)))
    assert 'HDR-CSP-MISSING' not in rules(detect(resp(headers=ro)))
    both = detect(resp(headers={**ro, 'Content-Security-Policy': "default-src 'self'"}))
    assert 'HDR-CSP-REPORT-ONLY' not in rules(both) and 'HDR-CSP-MISSING' not in rules(both)


def meta_page(csp=None, referrer=None, headers=None, tag_order='http-equiv-first'):
    tags = ''
    if csp is not None:
        tags += (f'<meta http-equiv="Content-Security-Policy" content="{csp}">' if tag_order == 'http-equiv-first'
                 else f'<meta content="{csp}" http-equiv=Content-Security-Policy>')
    if referrer:
        tags += f'<meta name="referrer" content="{referrer}">'
    return resp(headers=headers or {}, body=f'<html><head>{tags}</head><body></body></html>')


# ---- CSP via HTTP header vs <meta>: counted as a CSP, but never treated as equivalent
def test_meta_csp_is_not_reported_missing_but_is_reported_as_meta_only():
    f = detect(meta_page("default-src 'self'"))
    assert 'HDR-CSP-MISSING' not in rules(f)
    x = only(f, 'HDR-CSP-META-ONLY')
    assert x.severity == 'Informational' and 'only in a <meta http-equiv> tag' in x.evidence
    assert x.detection_method.startswith('Passive')


def test_header_csp_is_not_reported_as_meta_only():
    assert 'HDR-CSP-META-ONLY' not in rules(detect(resp(headers=GOOD)))
    both = detect(meta_page("default-src 'self'", headers={'Content-Security-Policy': "default-src 'self'"}))
    assert 'HDR-CSP-META-ONLY' not in rules(both)


def test_meta_attribute_order_and_quoting_variants():
    assert 'HDR-CSP-META-ONLY' in rules(detect(meta_page("default-src 'self'", tag_order='content-first')))
    body = '<meta http-equiv=\'Content-Security-Policy\' content=\'default-src https://x.test\'>'
    assert 'HDR-CSP-META-ONLY' in rules(detect(resp(body=body)))


def test_frame_ancestors_in_meta_is_ignored_and_does_not_suppress_xfo():
    f = detect(meta_page("default-src 'self'; frame-ancestors 'none'"))
    xfo = only(f, 'HDR-XFO-MISSING')                       # a meta frame-ancestors gives no clickjacking protection
    assert 'ignored by browsers' in xfo.evidence
    assert 'frame-ancestors' in only(f, 'HDR-CSP-META-ONLY').evidence
    # the same directive in the HTTP header DOES protect
    header = detect(resp(headers={**GOOD, 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"},
                         body='<html></html>'))
    assert header == []


def test_meta_frame_ancestors_does_not_weaken_a_real_x_frame_options():
    f = detect(meta_page("default-src 'self'; frame-ancestors 'none'", headers={'X-Frame-Options': 'DENY'}))
    assert 'HDR-XFO-MISSING' not in rules(f) and 'HDR-XFO-WEAK' not in rules(f)


def test_meta_csp_report_only_is_not_a_policy():
    body = '<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src \'self\'">'
    f = detect(resp(body=body))
    assert 'HDR-CSP-MISSING' in rules(f) and 'HDR-CSP-META-ONLY' not in rules(f)


def test_scan_meta_drops_directives_browsers_ignore():
    m = scan_meta('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; frame-ancestors \'none\'; '
                  'report-uri /r; sandbox">')
    assert m.early == [{'default-src': ["'self'"]}] and m.late == []
    assert m.ignored == ['frame-ancestors', 'report-uri', 'sandbox'] and len(m.raws) == 1
    assert scan_meta('<meta name="viewport" content="width=device-width">').early == []
    assert scan_meta(None) == ([], [], [], [], '', False, False)
    assert scan_meta('<meta http-equiv="Content-Security-Policy">').early == []


def test_meta_csp_weakness_is_judged_and_says_it_came_from_a_meta_tag():
    f = detect(meta_page("script-src 'unsafe-inline' *"))
    x = only(f, 'HDR-CSP-UNSAFE')
    assert 'delivered by a <meta> tag' in x.evidence and "'unsafe-inline'" in x.evidence
    assert 'HDR-CSP-META-ONLY' in rules(f)


def test_header_and_meta_policies_combine_and_are_weak_only_if_all_are_weak():
    strict_meta = meta_page("script-src 'self'", headers={'Content-Security-Policy': "script-src 'unsafe-inline'"})
    assert 'HDR-CSP-UNSAFE' not in rules(detect(strict_meta))           # the stricter meta policy also applies
    weak_both = meta_page("script-src *", headers={'Content-Security-Policy': "script-src 'unsafe-eval'"})
    x = only(detect(weak_both), 'HDR-CSP-UNSAFE')
    assert 'an HTTP header and a <meta> tag' in x.evidence


def test_meta_nonce_is_redacted_in_evidence():
    f = detect(meta_page("script-src 'nonce-METASECRET' 'unsafe-eval'"))
    assert 'METASECRET' not in ' '.join(x.evidence for x in f)


def test_meta_referrer_counts_as_present():
    f = detect(meta_page("default-src 'self'", referrer='no-referrer'))
    assert 'HDR-REFERRER-MISSING' not in rules(f)


# ---------------------------------------------------------------- HSTS / XCTO / XFO / Referrer / Permissions
@pytest.mark.parametrize('value,max_age', [('max-age=31536000', 31536000), ('MAX-AGE=10; includeSubDomains', 10),
                                           ('max-age="600"', 600), ('includeSubDomains', None),
                                           ('max-age=abc', None), ('max-age=', None), ('', None)])
def test_parse_hsts_max_age(value, max_age):
    assert parse_hsts_max_age(value) == max_age


@pytest.mark.parametrize('value,expect_finding', [
    ('max-age=31536000', False), ('max-age=15552000', False), ('max-age="31536000"', False),
    ('max-age=300', True), ('max-age=0', True), ('includeSubDomains', True), ('max-age=notanumber', True),
])
def test_hsts_weak_values(value, expect_finding):
    f = detect(resp(headers={**GOOD, 'Strict-Transport-Security': value}))
    assert ('HDR-HSTS-WEAK' in rules(f)) is expect_finding


def test_hsts_zero_is_called_out():
    x = only(detect(resp(headers={**GOOD, 'Strict-Transport-Security': 'max-age=0'})), 'HDR-HSTS-WEAK')
    assert 'switches HSTS off' in x.evidence


def test_content_type_options_values():
    assert 'HDR-XCTO-INVALID' in rules(detect(resp(headers={**GOOD, 'X-Content-Type-Options': 'sniff'})))
    assert 'HDR-XCTO-INVALID' not in rules(detect(resp(headers={**GOOD, 'X-Content-Type-Options': 'nosniff, nosniff'})))
    assert detect(resp(headers={**GOOD, 'X-Content-Type-Options': 'NOSNIFF'})) == []


def test_content_type_options_and_hsts_are_checked_on_non_html_but_document_headers_are_not():
    f = detect(resp('https://a.test/data.json', content_type='application/json', body='{}'))
    assert rules(f) == {'HDR-XCTO-MISSING', 'HDR-HSTS-MISSING'}       # CSP/XFO/Referrer/Permissions: documents only


@pytest.mark.parametrize('status', [301, 302, 304, 401, 403, 404, 500])
def test_non_success_responses_are_ignored(status):
    assert detect(resp(status=status)) == []


@pytest.mark.parametrize('value,weak', [('DENY', False), ('sameorigin', False), (' SAMEORIGIN ', False),
                                        ('ALLOW-FROM https://x.test', True), ('allowall', True)])
def test_x_frame_options_values(value, weak):
    f = detect(resp(headers={**GOOD, 'X-Frame-Options': value,
                             'Content-Security-Policy': "default-src 'self'"}))
    assert ('HDR-XFO-WEAK' in rules(f)) is weak


def test_frame_ancestors_supersedes_x_frame_options():
    csp = {'Content-Security-Policy': "default-src 'self'; frame-ancestors 'self'"}
    assert detect(resp(headers={**GOOD, **csp, 'X-Frame-Options': 'ALLOW-FROM x'})) == []
    headers = {k: v for k, v in GOOD.items() if k != 'X-Frame-Options'}
    assert detect(resp(headers={**headers, **csp})) == []


@pytest.mark.parametrize('value,effective', [
    ('no-referrer', 'no-referrer'), ('unsafe-url', 'unsafe-url'), ('UNSAFE-URL', 'unsafe-url'),
    ('unsafe-url, no-referrer', 'no-referrer'), ('no-referrer, unsafe-url', 'unsafe-url'),
    ('garbage', None), ('', None), ('origin, garbage', 'origin')])
def test_effective_referrer_policy(value, effective):
    assert effective_referrer_policy(value) == effective


def test_referrer_policy_findings():
    weak = detect(resp(headers={**GOOD, 'Referrer-Policy': 'unsafe-url'}))
    assert rules(weak) == {'HDR-REFERRER-WEAK'} and weak[0].severity == 'Low'
    assert detect(resp(headers={**GOOD, 'Referrer-Policy': 'unsafe-url, same-origin'})) == []
    assert detect(resp(headers={**GOOD, 'Referrer-Policy': 'nonsense'})) == []     # browser default applies: not flagged


def test_feature_policy_does_not_satisfy_the_permissions_policy_check():
    headers = {k: v for k, v in GOOD.items() if k != 'Permissions-Policy'}
    x = only(detect(resp(headers={**headers, 'Feature-Policy': "camera 'none'"})), 'HDR-PERMISSIONS-MISSING')
    assert 'Only the deprecated Feature-Policy header was found' in x.evidence and x.severity == 'Informational'
    plain = only(detect(resp(headers=headers)), 'HDR-PERMISSIONS-MISSING')
    assert 'Feature-Policy header is absent too' in plain.evidence
    assert detect(resp(headers={**headers, 'Permissions-Policy': 'camera=()', 'Feature-Policy': "camera 'none'"})) == []


def test_pages_failing_the_same_rule_differently_keep_each_distinct_evidence():
    f = detect(resp('https://a.test/1', headers={**GOOD, 'Strict-Transport-Security': 'max-age=10'}),
               resp('https://a.test/2', headers={**GOOD, 'Strict-Transport-Security': 'max-age=0'}),
               resp('https://a.test/3', headers={**GOOD, 'Strict-Transport-Security': 'max-age=10'}))
    x = only(f, 'HDR-HSTS-WEAK')
    assert x.affected_urls == ['https://a.test/1', 'https://a.test/2', 'https://a.test/3']
    assert 'max-age=10' in x.evidence and 'switches HSTS off' in x.evidence      # the worst case stays visible
    assert x.evidence.count('max-age=10,') == 1                                  # identical variants are not repeated
    assert '3 pages are affected in total.' in x.evidence


def test_variant_evidence_is_capped():
    pages = [resp(f'https://a.test/{i}', headers={**GOOD, 'Strict-Transport-Security': f'max-age={i}'})
             for i in range(10)]
    x = only(detect(*pages), 'HDR-HSTS-WEAK')
    assert len(x.affected_urls) == 10 and x.evidence.count('sent Strict-Transport-Security') == 3


# ---------------------------------------------------------------- evidence hygiene
def test_query_strings_inside_csp_urls_are_masked_in_evidence():
    f = detect(resp(headers={**GOOD, 'Content-Security-Policy':
                             "script-src 'unsafe-eval'; report-uri https://r.test/csp?token=ABC123&key=zzzSECRET"}))
    blob = ' '.join(x.evidence for x in f)
    assert 'zzzSECRET' not in blob and 'ABC123' not in blob and '?[query redacted]' in blob and 'r.test/csp' in blob

def test_evidence_lists_header_names_never_values():
    f = detect(resp(headers={'Set-Cookie': 'session=TOPSECRETVALUE; HttpOnly',
                             'Authorization': 'Bearer abcdef1234567890', 'X-Internal': 'hunter2'}))
    blob = ' '.join(x.evidence for x in f)
    assert 'set-cookie' in blob and 'TOPSECRETVALUE' not in blob and 'hunter2' not in blob and 'abcdef1234567890' not in blob


# ---------------------------------------------------------------- malformed input
class ExplodingResponse(HttpResponse):
    def text(self):
        raise RuntimeError('decoder exploded')


def test_malformed_responses_never_raise():
    garbage_body = bytes(range(256)) * 10
    cases = [
        resp(body=garbage_body, headers=GOOD),
        resp(content_type='text/html;;;charset=\x00bogus', headers=GOOD),
        resp(content_type=None, headers=GOOD),                                  # no Content-Type: not a document
        resp(headers=[('Content-Security-Policy', ''), ('Strict-Transport-Security', ';;;;'),
                      ('X-Frame-Options', ''), ('Referrer-Policy', ',,,'), ('X-Content-Type-Options', '')]),
        resp(headers=[('Content-Security-Policy', ';;;,,,;;'), ('Content-Security-Policy', "script-src")]),
        resp(headers=[('content-security-policy', "script-src 'self'"), ('CONTENT-SECURITY-POLICY', 'x' * 100_000)]),
        resp(body=''),
    ]
    for case in cases:
        detect(case)                                     # must not raise
    assert detect() == []


def test_one_broken_page_does_not_hide_findings_from_other_pages():
    f = detect(resp('https://a.test/boom', cls=ExplodingResponse), resp('https://a.test/fine'))
    assert 'HDR-CSP-MISSING' in rules(f)
    assert 'https://a.test/boom' not in only(f, 'HDR-CSP-MISSING').affected_urls


def test_detector_makes_no_requests_of_its_own():
    """Passive guarantee: the client is None here, so any request attempt would raise."""
    detect(resp(), resp('http://a.test/'))


# ---------------------------------------------------------------- registry / processor integration
def test_registered_through_the_existing_registry():
    names = {d.name for d in get_detectors({'security_headers'})}
    assert 'security-headers' in names
    assert 'security-headers' not in {d.name for d in get_detectors({'cookie_security'})}


def test_informational_findings_survive_the_result_processor():
    f = detect(resp(headers={k: v for k, v in GOOD.items() if k not in ('Referrer-Policy', 'Permissions-Policy')}))
    assert {x.severity for x in f} == {'Informational'} and len(f) == 2
    merged = dedupe(f + detect(resp(headers={k: v for k, v in GOOD.items() if k != 'Referrer-Policy'})))
    assert len(merged) == 2 and all(x.severity in SEVERITIES for x in merged)


def test_dedupe_merges_findings_from_separate_runs_and_keeps_strongest_severity():
    a = only(detect(resp('https://a.test/1')), 'HDR-CSP-MISSING')
    b = only(detect(resp('https://a.test/2')), 'HDR-CSP-MISSING')
    assert a.fingerprint() == b.fingerprint()
    (merged,) = dedupe([a, b])
    assert merged.affected_urls == ['https://a.test/1', 'https://a.test/2']


# ---------------------------------------------------------------- end to end through the real engine
@pytest.fixture
def engine(lab_config, resolver, clock):
    def factory(target, config, resolver):
        return ScanHTTPClient(target, config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    return ScanEngine(config=lab_config, resolver=resolver, client_factory=factory)


SH = {'security_headers'}          # engine runs are limited by category; the real registry is left untouched


def hdrs(extra=None, drop=()):
    base = {'Content-Type': 'text/html', **GOOD}
    base.pop('Strict-Transport-Security')                   # plain-HTTP lab server: HSTS not applicable
    for d in drop:
        base.pop(d, None)
    return {**base, **(extra or {})}


def test_engine_scan_reports_gaps_with_real_crawled_responses(make_server, engine):
    srv = make_server({})
    srv.routes['/'] = (200, hdrs(drop=['Content-Security-Policy']), b'<a href="/a">a</a>')
    srv.routes['/a'] = (200, hdrs(drop=['Content-Security-Policy', 'X-Frame-Options']), b'<p>a</p>')
    out = engine.run(srv.base + '/', True, SH)
    assert out.status == 'completed' and out.pages_crawled == 2
    by_rule = {f.extra['rule']: f for f in out.findings}
    assert set(by_rule) == {'HDR-CSP-MISSING', 'HDR-XFO-MISSING'}
    assert len(by_rule['HDR-CSP-MISSING'].affected_urls) == 2 and len(by_rule['HDR-XFO-MISSING'].affected_urls) == 1
    assert out.requests_used == len(srv.seen) == 2           # the detector added no requests
    assert out.severity_counts()['Medium'] == 1 and out.severity_counts()['Low'] == 1


def test_engine_scan_of_hardened_server_reports_nothing(make_server, engine):
    srv = make_server({'/': (200, hdrs(), b'<a href="/a">a</a>'), '/a': (200, hdrs(), b'<p>a</p>')})
    out = engine.run(srv.base + '/', True, SH)
    assert out.status == 'completed' and out.findings == [] and out.errors == []


def test_engine_scan_over_https_checks_hsts(make_server, engine, make_cert):
    srv = make_server({'/': (200, hdrs(), b'<p>secure</p>')}, tls=make_cert('lab.test', 'lab.test'))
    out = engine.run(srv.base + '/', True, SH)               # self-signed: the crawler still analyses the start page
    assert {f.extra['rule'] for f in out.findings} == {'HDR-HSTS-MISSING'}
    srv.routes['/'] = (200, {**hdrs(), 'Strict-Transport-Security': 'max-age=31536000'}, b'<p>secure</p>')
    assert engine.run(srv.base + '/', True, SH).findings == []


def test_engine_redacts_and_serializes_findings(make_server, engine):
    srv = make_server({'/': (200, hdrs(drop=['Content-Security-Policy']), b'x')})
    out = engine.run(srv.base + '/', True, SH)
    d = out.findings[0].to_dict()
    for key in ('title', 'category', 'severity', 'confidence', 'affected_url', 'evidence', 'impact',
                'remediation', 'reference', 'detection_method', 'fingerprint'):
        assert d[key]
    assert not any('cvss' in k.lower() for k in d)


SECRET_URL = 'https://u:hunter2@a.test:8443/p;jsessionid=PATHSECRET/q?sig=ZZSECRET123&session=SESSSECRET&bare#access_token=FRAGSECRET'
LEAKS = ('ZZSECRET123', 'SESSSECRET', 'FRAGSECRET', 'PATHSECRET', 'hunter2', 'access_token')


def test_internal_identity_is_raw_but_everything_outward_is_sanitized():
    f = detect(resp(SECRET_URL))
    assert f
    for x in f:
        assert x.affected_urls == [SECRET_URL]                                   # internal page identity, unmasked
        assert not any(leak in x.evidence for leak in LEAKS)                     # evidence masked
        assert x.display_urls == ['https://a.test:8443/p;jsessionid=[redacted]/q?sig=[redacted]&session=[redacted]&[redacted]']
        assert x.display_url == x.display_urls[0] == x.to_dict()['affected_url']
        assert 'a.test:8443/p' in x.display_url and '/q?sig=' in x.display_url   # page remains identifiable
        assert not any(leak in repr(x) for leak in LEAKS)                        # repr (logs, pytest output) hides URLs


def test_complete_serialized_output_contains_no_url_secrets():
    """Walks every value of Finding.to_dict() (and its JSON form), not just evidence and affected_urls."""
    import json
    f = detect(resp(SECRET_URL, headers={'Content-Security-Policy': "script-src 'unsafe-eval'; report-uri /r?token=Q1Q2Q3"}))
    assert len(f) >= 3
    for x in f:
        d = x.to_dict()
        assert set(d) == {'rule_id', 'title', 'category', 'severity', 'confidence', 'description', 'affected_urls',
                          'affected_url', 'evidence', 'impact', 'remediation', 'reference', 'detection_method',
                          'fingerprint'}
        blob = json.dumps(d)
        for leak in LEAKS + ('Q1Q2Q3',):
            assert leak not in blob, (x.rule_id, leak)
        assert d['affected_url'] == d['affected_urls'][0] and '#' not in blob.replace('[redacted]', '')


def test_to_dict_is_an_output_guard_even_for_findings_not_built_by_the_catalog():
    """A detector that bypasses build_finding still cannot leak through serialization."""
    from scanner.models import Finding
    raw = Finding(rule_id='X-1', title=f'Issue at {SECRET_URL}', category='security_headers', severity='Low',
                  confidence='Confirmed', description=f'See {SECRET_URL}.', affected_urls=[SECRET_URL, SECRET_URL.replace('/q?', '/other?')],
                  evidence=f'GET {SECRET_URL} (token=abcdef123456)', impact='i', remediation=f'Fix {SECRET_URL}',
                  reference='ref', detection_method='test')
    assert raw.affected_urls[0] == SECRET_URL                       # in-memory value unchanged (fingerprints need it)
    blob = str(raw.to_dict())
    assert not any(leak in blob for leak in LEAKS + ('abcdef123456',))
    assert len(raw.to_dict()['affected_urls']) == 2                 # distinct pages stay distinct


def test_sanitize_url_properties():
    from scanner.sanitize import sanitize_url, sanitize_urls, scrub_text
    assert sanitize_url('https://A.test') == 'https://a.test'
    assert sanitize_url('http://a.test/x?a=1&a=2') == 'http://a.test/x?a=[redacted]&a=[redacted]'
    assert sanitize_url('http://[::1]:8080/x?k=v#f') == 'http://[::1]:8080/x?k=[redacted]'
    assert sanitize_url('http://a.test:99999/x?q=SECRET') == 'http://a.test:99999/x'          # malformed: query dropped
    assert 'SECRET' not in sanitize_url('not a url ?q=SECRET#frag')
    for u in (SECRET_URL, 'https://a.test/', 'http://[::1]/', '/rel?x=1', ''):
        assert sanitize_url(sanitize_url(u)) == sanitize_url(u)                              # idempotent
    assert sanitize_urls(['http://a.test/?x=1', 'http://a.test/?x=2']) == ['http://a.test/?x=[redacted]'] * 2   # count preserved
    assert scrub_text('see http://a.test/p?k=v, ok') == 'see http://a.test/p?k=[redacted], ok'


def test_static_catalog_text_is_unchanged_by_the_serialization_guard():
    """The guard must not mangle legitimate rule text (false redaction)."""
    from scanner.rules import RULES
    from scanner.sanitize import scrub_text
    for rule in RULES.values():
        for text in (rule.title, rule.description, rule.impact_text, rule.remediation, rule.reference, rule.method):
            assert scrub_text(text) == text, (rule.id, text)


def test_engine_evidence_contains_no_url_query_secrets(make_server, engine):
    srv = make_server({'/': (200, {'Content-Type': 'text/html'}, b'x')})
    out = engine.run(srv.base + '/?sig=ZZSECRET123&session=SESSSECRET&page=2', True, SH)
    assert out.findings
    blob = json.dumps([f.to_dict() for f in out.findings])
    assert 'ZZSECRET123' not in blob and 'SESSSECRET' not in blob and '?sig=[redacted]&session=[redacted]' in blob


# ---------------------------------------------------------------- meta CSP placement
CSP_META = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'


def doc(head='', body='', **kw):
    return resp(body=f'<!doctype html><html><head>{head}</head><body>{body}</body></html>', **kw)


def test_meta_csp_first_in_head_is_early_full_coverage():
    f = detect(doc(f'<meta charset="utf-8"><title>t</title><base href="/">{CSP_META}'
                   '<script src="/a.js"></script><link rel="stylesheet" href="/a.css">'))
    assert 'HDR-CSP-META-ONLY' in rules(f) and 'HDR-CSP-META-LATE' not in rules(f) and 'HDR-CSP-MISSING' not in rules(f)


def raw_doc(markup):
    """A document without <html>/<head>/<body> wrappers, to test bare content placement."""
    return resp(body=markup)


@pytest.mark.parametrize('page,blocker', [
    (lambda: doc('<script src="/a.js"></script>' + CSP_META), '<script>'),
    (lambda: doc('<script>var x=1;</script>' + CSP_META), '<script>'),
    (lambda: doc('<link rel="stylesheet" href="/a.css">' + CSP_META), '<link rel="stylesheet">'),
    (lambda: doc('<style>b{}</style>' + CSP_META), '<style>'),
    (lambda: doc('<link rel="preload" href="/f.woff2" as="font">' + CSP_META), '<link rel="preload">'),
    (lambda: raw_doc('<img src="/x.png">' + CSP_META), '<img>'),
    (lambda: raw_doc('<iframe src="/f"></iframe>' + CSP_META), '<iframe>'),
    (lambda: raw_doc('<div>hello</div>' + CSP_META), 'page content (<div>)'),
    (lambda: doc('', CSP_META), 'the start of <body>'),                 # a meta tag inside <body> is late too
])
def test_late_meta_csp_is_not_full_protection(page, blocker):
    f = detect(page())
    assert 'HDR-CSP-MISSING' not in rules(f) and 'HDR-CSP-META-ONLY' not in rules(f)
    late = only(f, 'HDR-CSP-META-LATE')
    assert late.severity == 'Low' and blocker in late.evidence and 'earlier content is not covered' in late.evidence
    assert late.confidence == 'Confirmed' and late.detection_method.startswith('Passive')


def test_late_meta_is_rated_between_meta_only_and_missing():
    sev = lambda r, h, b='': only(detect(doc(h, b)), r).severity
    assert sev('HDR-CSP-META-ONLY', CSP_META) == 'Informational'
    assert sev('HDR-CSP-META-LATE', '<script src=a.js></script>' + CSP_META) == 'Low'
    assert sev('HDR-CSP-MISSING', '') == 'Medium'


def test_late_meta_policy_is_not_judged_for_weakness_or_used_to_satisfy_the_check():
    weak_late = '<script src=a.js></script><meta http-equiv="Content-Security-Policy" content="script-src *">'
    f = detect(doc(weak_late))
    assert 'HDR-CSP-UNSAFE' not in rules(f) and 'HDR-CSP-META-LATE' in rules(f)


def test_early_meta_wins_when_a_late_duplicate_exists():
    f = detect(doc(CSP_META + '<script src=a.js></script>' + CSP_META))
    assert 'HDR-CSP-META-ONLY' in rules(f) and 'HDR-CSP-META-LATE' not in rules(f)


def test_header_csp_makes_meta_placement_irrelevant():
    f = detect(doc('<script src=a.js></script>' + CSP_META, headers={'Content-Security-Policy': "default-src 'self'"}))
    assert not {'HDR-CSP-META-LATE', 'HDR-CSP-META-ONLY', 'HDR-CSP-MISSING'} & rules(f)


def test_late_meta_frame_ancestors_is_still_ignored():
    late = '<script src=a.js></script><meta http-equiv="Content-Security-Policy" content="frame-ancestors \'none\'">'
    f = detect(doc(late))
    assert 'ignored by browsers' in only(f, 'HDR-XFO-MISSING').evidence


@pytest.mark.parametrize('markup', [
    '<!-- ' + CSP_META + ' -->',                                              # commented out
    '<script>document.write(\'' + CSP_META + '\')</script>',                  # tag text inside a script
    '<noscript>' + CSP_META + '</noscript>',                                  # not active when scripting is on
    '<template>' + CSP_META + '</template>',
    '<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src \'self\'">',
])
def test_meta_lookalikes_do_not_count_as_a_csp(markup):
    f = detect(doc(markup))
    assert 'HDR-CSP-MISSING' in rules(f) and not {'HDR-CSP-META-ONLY', 'HDR-CSP-META-LATE'} & rules(f)


def test_meta_referrer_in_a_comment_does_not_count():
    assert 'HDR-REFERRER-MISSING' in rules(detect(doc('<!-- <meta name="referrer" content="no-referrer"> -->')))
    assert 'HDR-REFERRER-MISSING' not in rules(detect(doc('<meta name="referrer" content="no-referrer">')))


def test_canonical_link_and_other_non_loading_elements_do_not_make_meta_late():
    f = detect(doc('<link rel="canonical" href="/c"><meta name="viewport" content="width=device-width">' + CSP_META))
    assert 'HDR-CSP-META-ONLY' in rules(f) and 'HDR-CSP-META-LATE' not in rules(f)


def test_html_entities_in_meta_content_are_decoded():
    m = scan_meta('<meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;">')
    assert m.early == [{'default-src': ["'self'"]}]


def test_unparseable_or_hostile_markup_is_handled_conservatively_without_raising():
    junk = ['<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"', '<<<>>><meta', '<script>' * 50,
            '<meta ' + 'a=b ' * 5000 + '>', '<' * 100_000]
    for body in junk:
        assert 'HDR-CSP-MISSING' in rules(detect(resp(body=body)))    # nothing reliable found -> reported missing
    detect(resp(body='\x00<meta http-equiv=content-security-policy content=\x00>'))      # nonsense policy: must not raise


def test_meta_beyond_the_scan_window_is_not_seen_and_is_reported_missing():
    f = detect(doc('<!-- ' + 'x' * 250_000 + ' -->' + CSP_META))
    assert 'HDR-CSP-MISSING' in rules(f)


def test_engine_reports_late_and_early_meta_csp_with_real_responses(make_server, engine):
    H = {k: v for k, v in hdrs(drop=['Content-Security-Policy']).items()}
    srv = make_server({'/': (200, H, ('<head><script src="/a.js"></script>' + CSP_META + '</head><a href="/b">b</a>').encode()),
                       '/b': (200, H, ('<head>' + CSP_META + '</head>').encode())})
    out = engine.run(srv.base + '/', True, SH)
    by = {f.extra['rule']: f for f in out.findings}
    assert set(by) == {'HDR-CSP-META-LATE', 'HDR-CSP-META-ONLY'}
    assert by['HDR-CSP-META-LATE'].affected_urls == [srv.base + '/'] and by['HDR-CSP-META-ONLY'].affected_urls == [srv.base + '/b']


# ---------------------------------------------------------------- evidence ranking by importance
def hsts_page(i, value):
    return resp(f'https://a.test/{i}', headers={**GOOD, 'Strict-Transport-Security': value})


def test_most_important_variant_after_three_milder_ones_is_not_hidden():
    pages = [hsts_page(1, 'max-age=100'), hsts_page(2, 'max-age=200'), hsts_page(3, 'max-age=300'),
             hsts_page(4, 'max-age=0')]                                # the worst case arrives 4th
    x = only(detect(*pages), 'HDR-HSTS-WEAK')
    assert 'switches HSTS off' in x.evidence                           # shown although three variants came first
    assert x.evidence.index('switches HSTS off') < x.evidence.index('max-age=100')      # and listed first
    assert '1 other distinct configuration(s)' in x.evidence and 'max-age=300' not in x.evidence
    assert len(x.affected_urls) == 4 and '4 pages are affected in total.' in x.evidence


def test_invalid_and_zero_hsts_both_survive_many_earlier_variants():
    pages = [hsts_page(i, f'max-age={1000 * i}') for i in range(1, 8)]
    pages += [hsts_page(8, 'includeSubDomains'), hsts_page(9, 'max-age=notanumber'), hsts_page(10, 'max-age=0')]
    x = only(detect(*pages), 'HDR-HSTS-WEAK')
    zero, invalid = x.evidence.index('switches HSTS off'), x.evidence.index('no valid max-age')
    assert zero < invalid < x.evidence.index('max-age=1000')           # 0 first, invalid second, then the shortest valid one
    # 7 numeric + 'invalid' (both invalid values share one variant) + 0 = 9 variants, 3 shown
    assert x.evidence.count('sent Strict-Transport-Security') == 3 and '6 other distinct' in x.evidence


def test_shorter_hsts_lifetime_outranks_longer_one():
    pages = [hsts_page(i, f'max-age={v}') for i, v in enumerate((9000000, 8000000, 7000000, 6000000, 60), 1)]
    x = only(detect(*pages), 'HDR-HSTS-WEAK')
    assert 'max-age=60,' in x.evidence and 'max-age=9000000' not in x.evidence


def test_weak_csp_with_more_problems_outranks_earlier_milder_ones():
    mild = ["script-src 'unsafe-eval'", 'script-src *', 'script-src https:']
    pages = [resp(f'https://a.test/{i}', headers={**GOOD, 'Content-Security-Policy': p}) for i, p in enumerate(mild, 1)]
    pages.append(resp('https://a.test/4', headers={**GOOD, 'Content-Security-Policy':
                                                   "script-src 'unsafe-inline' 'unsafe-eval' * data:"}))
    x = only(detect(*pages), 'HDR-CSP-UNSAFE')
    assert x.evidence.startswith('GET https://a.test/4')               # four problems outrank three single-problem policies
    assert "'unsafe-inline' without a nonce or hash" in x.evidence and '1 other distinct' in x.evidence


def test_equal_importance_variants_keep_page_order():
    pages = [resp(f'https://a.test/{i}', headers={**GOOD, 'Content-Security-Policy': "default-src 'self'",
                                                  'X-Frame-Options': v})
             for i, v in enumerate(('ALLOW-FROM a', 'ALLOW-FROM b', 'ALLOW-FROM c', 'ALLOW-FROM d'), 1)]
    x = only(detect(*pages), 'HDR-XFO-WEAK')
    assert 'ALLOW-FROM a' in x.evidence and 'ALLOW-FROM c' in x.evidence and 'ALLOW-FROM d' not in x.evidence
    assert x.evidence.index('ALLOW-FROM a') < x.evidence.index('ALLOW-FROM b') < x.evidence.index('ALLOW-FROM c')


def test_ranking_survives_thousands_of_variants_with_bounded_memory():
    """More distinct variants than the tracking table holds: the worst case must still win a slot."""
    from scanner.detectors.security_headers import _Collector
    pages = [hsts_page(i, f'max-age={i + 1}') for i in range(300)] + [hsts_page(999, 'max-age=0'),
                                                                     hsts_page(1000, 'max-age=notanumber')]
    x = only(detect(*pages), 'HDR-HSTS-WEAK')
    assert 'switches HSTS off' in x.evidence and 'no valid max-age' in x.evidence and len(x.affected_urls) == 302
    assert x.evidence.index('switches HSTS off') < x.evidence.index('no valid max-age') < x.evidence.index('max-age=1,')
    c = _Collector()
    for i in range(1000):
        c.add('HDR-HSTS-WEAK', f'https://a.test/{i}', f'ev{i}', variant=i, weight=i % 50)
    assert len(c.items['HDR-HSTS-WEAK']['variants']) <= _Collector.MAX_TRACKED


def test_late_low_weight_variant_does_not_evict_better_ones():
    from scanner.detectors.security_headers import _Collector
    c = _Collector()
    for i in range(_Collector.MAX_TRACKED):
        c.add('HDR-HSTS-WEAK', f'https://a.test/{i}', f'ev{i}', variant=i, weight=60)
    c.add('HDR-HSTS-WEAK', 'https://a.test/late', 'late-mild', variant='late', weight=10)
    c.add('HDR-HSTS-WEAK', 'https://a.test/worse', 'late-worst', variant='worse', weight=100)
    kept = {v[2] for v in c.items['HDR-HSTS-WEAK']['variants'].values()}
    assert 'late-mild' not in kept and 'late-worst' in kept


# ================================================================ Round 3 regression tests
# ---------------------------------------------------------------- 1. HSTS coverage
@pytest.mark.parametrize('content_type,body', [
    ('application/json', '{}'), ('text/plain', 'ok'), ('image/png', b'\x89PNG'), ('application/pdf', b'%PDF'),
    ('text/css', 'a{}'), (None, 'raw')])
def test_hsts_is_judged_on_https_responses_of_any_content_type(content_type, body):
    f = detect(resp('https://a.test/x', content_type=content_type, body=body, headers={'X-Content-Type-Options': 'nosniff'}))
    assert rules(f) == {'HDR-HSTS-MISSING'}                      # nothing document-only is reported
    ok = detect(resp('https://a.test/x', content_type=content_type, body=body,
                     headers={'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=31536000'}))
    assert ok == []
    weak = detect(resp('https://a.test/x', content_type=content_type, body=body,
                       headers={'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=60'}))
    assert rules(weak) == {'HDR-HSTS-WEAK'}


def test_hsts_is_still_ignored_over_plain_http_for_every_content_type_and_status():
    for ct in ('application/json', 'text/html'):
        for status in (200, 301, 404):
            f = detect(resp('http://a.test/x', status=status, content_type=ct, headers={'Strict-Transport-Security': 'max-age=0'}))
            assert 'HDR-HSTS-WEAK' not in rules(f) and 'HDR-HSTS-MISSING' not in rules(f)


@pytest.mark.parametrize('status', [100, 301, 302, 304, 400, 401, 403, 404, 500, 503])
def test_hsts_missing_is_reported_from_2xx_only(status):
    assert 'HDR-HSTS-MISSING' not in rules(detect(resp('https://a.test/x', status=status, content_type='application/json')))


@pytest.mark.parametrize('status', [200, 201, 204, 206])
def test_hsts_missing_is_reported_from_every_2xx(status):
    assert 'HDR-HSTS-MISSING' in rules(detect(resp('https://a.test/x', status=status, content_type='application/json')))


@pytest.mark.parametrize('status', [200, 204, 301, 404, 500])
def test_present_but_weak_hsts_is_reported_from_any_https_status(status):
    """max-age=0 on a redirect or error page still switches HSTS off in the browser."""
    f = detect(resp('https://a.test/x', status=status, content_type='application/json',
                    headers={'Strict-Transport-Security': 'max-age=0'}))
    assert 'HDR-HSTS-WEAK' in rules(f) and 'switches HSTS off' in only(f, 'HDR-HSTS-WEAK').evidence
    good = detect(resp('https://a.test/x', status=status, content_type='application/json',
                       headers={'Strict-Transport-Security': 'max-age=31536000'}))
    assert 'HDR-HSTS-WEAK' not in rules(good)


def test_hsts_check_is_independent_of_the_html_document_checks():
    f = detect(resp('https://a.test/boom', cls=ExplodingResponse))          # text() raises: document checks cannot run
    assert 'HDR-HSTS-MISSING' in rules(f) and 'HDR-XCTO-MISSING' in rules(f)


def test_one_failing_check_does_not_hide_the_other_checks_on_the_same_page():
    class CspExplodes(HttpResponse):
        def header_all(self, name):
            if name == 'content-security-policy':
                raise RuntimeError('boom')
            return super().header_all(name)
    f = detect(resp(cls=CspExplodes))
    assert {'HDR-HSTS-MISSING', 'HDR-XCTO-MISSING', 'HDR-REFERRER-MISSING', 'HDR-PERMISSIONS-MISSING'} <= rules(f)
    assert not {'HDR-CSP-MISSING', 'HDR-XFO-MISSING'} & rules(f)


# ---------------------------------------------------------------- 2. text before a meta CSP
@pytest.mark.parametrize('markup,blocker', [
    ('Hello world ' + CSP_META, 'text content'),                                    # bare fragment, plain text
    ('<html><head>stray text' + CSP_META, 'text content'),                           # text directly in <head>
    ('<<< text' + CSP_META, 'text content'),                                         # malformed angle brackets
    ('<<<>>>' + CSP_META, 'text content'),
    ('x' + CSP_META, 'text content'),
    ('&nbsp;' + CSP_META, 'text content'),                                           # a no-break space is content
    (' ' + CSP_META, 'text content'),
    ('&#8203;' + CSP_META, 'text content'),                                          # zero-width space
    ('<meta charset="utf-8">some text' + CSP_META, 'text content'),
    ('<title>t</title>after title text' + CSP_META, 'text content'),
    ('<b>' + CSP_META, 'page content (<b>)'),
])
def test_non_blank_text_before_a_meta_csp_makes_it_late(markup, blocker):
    f = detect(raw_doc(markup))
    late = only(f, 'HDR-CSP-META-LATE')
    assert blocker in late.evidence and not {'HDR-CSP-META-ONLY', 'HDR-CSP-MISSING'} & rules(f)


@pytest.mark.parametrize('markup', [
    CSP_META,
    '   \n\t  \r\n' + CSP_META,                                                       # whitespace only
    '﻿' + CSP_META,                                                             # byte-order mark
    '<!-- comment -->' + CSP_META,                                                    # comments
    '<!-- a --> \n <!-- b -->\n' + CSP_META,
    '<!DOCTYPE html>\n' + CSP_META,
    '<?xml version="1.0"?>\n' + CSP_META,
    '<html>\n<head>\n  <title>Hello text in a title</title>\n  ' + CSP_META,         # <title> text is not content
    '<html><head><meta charset="utf-8"><base href="/"><link rel="canonical" href="/c">' + CSP_META,
    '<noscript>text in noscript</noscript>' + CSP_META,                              # inactive when scripting is on
    '<template>text</template>' + CSP_META,
    CSP_META + 'text after the tag is covered by it',
])
def test_whitespace_comments_and_head_metadata_do_not_make_a_meta_csp_late(markup):
    f = detect(raw_doc(markup))
    assert 'HDR-CSP-META-ONLY' in rules(f) and 'HDR-CSP-META-LATE' not in rules(f)


@pytest.mark.parametrize('markup', ['<<<text' + CSP_META, 'a<b' + CSP_META, '<text' + CSP_META])
def test_meta_swallowed_by_a_bogus_tag_is_not_a_meta_csp(markup):
    """`<text<meta ...>` is ONE unknown tag (name 'text<meta') in browsers and in this parser, so there is no
    meta element and no policy: reported as missing, the conservative outcome."""
    f = detect(raw_doc(markup))
    assert 'HDR-CSP-MISSING' in rules(f) and not {'HDR-CSP-META-ONLY', 'HDR-CSP-META-LATE'} & rules(f)


def test_text_that_only_appears_inside_a_comment_or_script_string_is_not_content():
    f = detect(raw_doc('<!-- lots of text here -->' + CSP_META))
    assert 'HDR-CSP-META-ONLY' in rules(f)
    f = detect(raw_doc('<script>/* text */</script>' + CSP_META))
    assert 'HDR-CSP-META-LATE' in rules(f)                                           # the script itself is the blocker


def test_meta_after_text_inside_head_of_full_document_is_late():
    f = detect(doc('Stray text' + CSP_META))
    assert 'text content' in only(f, 'HDR-CSP-META-LATE').evidence


# ---------------------------------------------------------------- 3. frame-ancestors validation
@pytest.mark.parametrize('tokens,state', [
    # effective list names only some origins (or none): restrictive
    (["'none'"], 'restrictive'), (["'self'"], 'restrictive'), (["'none'", "'self'"], 'restrictive'),
    (['https://partner.example'], 'restrictive'), (['*.example.com', "'self'"], 'restrictive'),
    (['example.com:8443', 'http://localhost:3000'], 'restrictive'),
    # EMPTY effective list matches no ancestor, so it blocks framing: restrictive (never weak)
    ([], 'restrictive'),                                                   # empty directive
    (["'unsafe-inline'"], 'restrictive'), (['!!!'], 'restrictive'), (["'self"], 'restrictive'),
    (['https://'], 'restrictive'), (['//'], 'restrictive'), (["'nonce-abc'"], 'restrictive'),
    (['!!!', '???', "'bogus'"], 'restrictive'),                            # all invalid
    (["'unsafe-inline'", 'https://ok.example'], 'restrictive'),            # invalid tokens are ignored
    # permissive effective lists
    (['*'], 'permissive'), (['https:'], 'permissive'), (["'self'", '*'], 'permissive'),
    (["'self'", 'https:'], 'permissive'), (['data:'], 'permissive'),
    (['!!!', '*'], 'permissive'),                                           # an invalid token does not hide a '*'
    (["'none'", '*'], 'permissive'),                                        # 'none' is ignored next to other sources
])
def test_classify_frame_ancestors(tokens, state):
    assert classify_frame_ancestors(tokens) == state


def fa_page(csp, **extra):
    return resp(headers={**{k: v for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')},
                         'Content-Security-Policy': csp, **extra})


@pytest.mark.parametrize('csp', ["default-src 'self'; frame-ancestors 'none'", "frame-ancestors 'self'",
                                 "default-src 'self'; frame-ancestors https://partner.example 'self'",
                                 "frame-ancestors *.example.com"])
def test_valid_restrictive_frame_ancestors_is_protection(csp):
    assert detect(fa_page(csp)) == []


# ---- missing vs empty vs invalid vs 'none' / 'self' / hosts / permissive, and the X-Frame-Options interaction
XFO_CASES = [None, 'DENY', 'SAMEORIGIN', 'ALLOW-FROM https://x.test', 'garbage']


def fa_rules(csp, xfo=None, **extra):
    headers = {**{k: v for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')}, **extra}
    if csp is not None:
        headers['Content-Security-Policy'] = csp
    if xfo is not None:
        headers['X-Frame-Options'] = xfo
    return rules(detect(resp(headers=headers)))


def test_missing_frame_ancestors_is_not_an_empty_directive_and_x_frame_options_decides():
    csp = "default-src 'self'"                                       # directive ABSENT
    assert fa_rules(csp) == {'HDR-XFO-MISSING'}                      # nothing restricts framing
    assert fa_rules(csp, 'DENY') == set() and fa_rules(csp, 'SAMEORIGIN') == set()
    assert fa_rules(csp, 'ALLOW-FROM https://x.test') == {'HDR-XFO-WEAK'}
    assert fa_rules(csp, 'garbage') == {'HDR-XFO-WEAK'}
    assert 'HDR-FRAME-ANCESTORS-WEAK' not in fa_rules(csp)
    assert fa_rules(None) == {'HDR-CSP-MISSING', 'HDR-XFO-MISSING'}   # no CSP at all: same, XFO consulted


@pytest.mark.parametrize('csp', ["default-src 'self'; frame-ancestors", "default-src 'self'; frame-ancestors;",
                                 "default-src 'self'; frame-ancestors ;", "frame-ancestors", "frame-ancestors;",
                                 "FRAME-ANCESTORS"])
@pytest.mark.parametrize('xfo', XFO_CASES)
def test_empty_frame_ancestors_matches_no_ancestor_and_blocks_framing(csp, xfo):
    """A PRESENT empty directive is enforced: empty source list = 'none'. X-Frame-Options is ignored."""
    assert fa_rules(csp, xfo) == set()                              # restrictive: no weak finding, no XFO finding


@pytest.mark.parametrize('csp', ["frame-ancestors 'unsafe-inline'", "default-src 'self'; frame-ancestors !!! ???",
                                 "frame-ancestors 'self", "frame-ancestors https://", "frame-ancestors 'nonce-abc'",
                                 "frame-ancestors 'bogus' ??? ***bad"])
@pytest.mark.parametrize('xfo', XFO_CASES)
def test_all_invalid_frame_ancestors_expressions_leave_an_empty_restrictive_list(csp, xfo):
    assert fa_rules(csp, xfo) == set()                              # invalid tokens never turn a blocking list weak


@pytest.mark.parametrize('csp', ["frame-ancestors 'none'", "frame-ancestors 'NONE'", "FRAME-ANCESTORS 'None'",
                                 "frame-ancestors 'self'", "default-src 'self'; frame-ancestors 'self'",
                                 "frame-ancestors 'none' 'self'",
                                 "frame-ancestors https://partner.example", "frame-ancestors *.example.com 'self'",
                                 "frame-ancestors 'self' https://a.example:8443 http://localhost:3000",
                                 "frame-ancestors 'unsafe-inline' https://ok.example"])
@pytest.mark.parametrize('xfo', XFO_CASES)
def test_valid_restrictive_frame_ancestors_ignores_x_frame_options(csp, xfo):
    assert fa_rules(csp, xfo) == set()                              # even a bad or absent XFO: frame-ancestors governs


@pytest.mark.parametrize('csp', ["frame-ancestors *", "frame-ancestors https:", "frame-ancestors 'self' *",
                                 "frame-ancestors data:", "frame-ancestors !!! *", "frame-ancestors 'none' *",
                                 "frame-ancestors 'self' https:"])
@pytest.mark.parametrize('xfo', XFO_CASES)
def test_permissive_frame_ancestors_is_weak_and_x_frame_options_cannot_rescue_it(csp, xfo):
    f = detect(resp(headers={**{k: v for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')},
                             'Content-Security-Policy': csp, **({'X-Frame-Options': xfo} if xfo else {})}))
    x = only(f, 'HDR-FRAME-ANCESTORS-WEAK')
    assert x.confidence == 'Confirmed' and x.severity == 'Low' and 'ignored by browsers' in x.evidence
    assert not {'HDR-XFO-MISSING', 'HDR-XFO-WEAK'} & rules(f)


# ---- several policies: they all apply, so one blocking policy protects the page
def multi_page(*policies, as_fields=False, xfo=None):
    base = [(k, v) for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')]
    csp = [('Content-Security-Policy', p) for p in policies] if as_fields else [('Content-Security-Policy', ', '.join(policies))]
    return resp(headers=[('Content-Type', 'text/html')] + base + csp + ([('X-Frame-Options', xfo)] if xfo else []))


@pytest.mark.parametrize('as_fields', [False, True])
def test_frame_ancestors_across_multiple_policies(as_fields):
    r = lambda *p, **k: rules(detect(multi_page(*p, as_fields=as_fields, **k)))
    assert r("frame-ancestors 'none'", "frame-ancestors *") == set()          # one blocking policy wins
    assert r("frame-ancestors *", "frame-ancestors 'none'") == set()          # order is irrelevant
    assert r("frame-ancestors *", "frame-ancestors") == set()                  # an EMPTY directive blocks
    assert r("frame-ancestors *", "frame-ancestors !!!") == set()              # all-invalid = empty = blocks
    assert r("frame-ancestors *", "frame-ancestors https://a.example") == set()
    assert r("frame-ancestors *", "frame-ancestors https:") == {'HDR-FRAME-ANCESTORS-WEAK'}   # both permissive
    # a second policy WITHOUT the directive restricts nothing: absent is not empty
    assert r("frame-ancestors *", "default-src 'self'") == {'HDR-FRAME-ANCESTORS-WEAK'}
    assert r("frame-ancestors 'none'", "default-src 'self'") == set()
    assert r("default-src 'self'", "script-src 'self'") == {'HDR-XFO-MISSING'}
    assert r("default-src 'self'", "script-src 'self'", xfo='DENY') == set()


def test_duplicate_frame_ancestors_directive_in_one_policy_first_wins():
    assert fa_rules("frame-ancestors 'none'; frame-ancestors *") == set()
    assert fa_rules("frame-ancestors *; frame-ancestors 'none'") == {'HDR-FRAME-ANCESTORS-WEAK'}
    assert fa_rules("frame-ancestors; frame-ancestors *") == set()            # empty came first and blocks


def test_a_policy_made_only_of_frame_ancestors_is_a_valid_policy_not_a_malformed_one():
    f = fa_rules("frame-ancestors")
    assert 'HDR-CSP-MALFORMED' not in f and 'HDR-CSP-MISSING' not in f


def test_frame_ancestors_that_browsers_ignore_counts_as_absent():
    base = {k: v for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')}
    # Report-Only header: not enforced
    ro = rules(detect(resp(headers={**base, 'Content-Security-Policy': "default-src 'self'",
                                    'Content-Security-Policy-Report-Only': 'frame-ancestors'})))
    assert ro == {'HDR-XFO-MISSING'}
    # <meta> CSP: frame-ancestors (even an empty one) is ignored
    for directive in ('frame-ancestors', "frame-ancestors 'none'", 'frame-ancestors *'):
        f = detect(meta_page(f"default-src 'self'; {directive}"))
        assert 'HDR-XFO-MISSING' in rules(f) and 'HDR-FRAME-ANCESTORS-WEAK' not in rules(f)
    # malformed header contributes nothing
    assert 'HDR-XFO-MISSING' in rules(detect(resp(headers={**base, 'Content-Security-Policy': 'garbage frame-ancestors'})))


@pytest.mark.parametrize('csp,wording', [("frame-ancestors *", 'any site'), ("frame-ancestors https:", 'any site'),
                                         ("frame-ancestors 'self' *", 'any site')])
def test_permissive_frame_ancestors_is_not_protection_even_with_x_frame_options(csp, wording):
    f = detect(fa_page(csp, **{'X-Frame-Options': 'DENY'}))
    x = only(f, 'HDR-FRAME-ANCESTORS-WEAK')
    assert x.confidence == 'Confirmed' and wording in x.evidence and 'ignored by browsers' in x.evidence
    assert not {'HDR-XFO-MISSING', 'HDR-XFO-WEAK'} & rules(f)


def test_frame_ancestors_only_in_a_report_only_header_is_not_protection():
    f = detect(resp(headers={**{k: v for k, v in GOOD.items() if k not in ('Content-Security-Policy', 'X-Frame-Options')},
                             'Content-Security-Policy': "default-src 'self'",
                             'Content-Security-Policy-Report-Only': "frame-ancestors 'none'"}))
    assert 'HDR-XFO-MISSING' in rules(f)


def test_most_restrictive_of_several_policies_wins_for_frame_ancestors():
    two = [('Content-Security-Policy', "frame-ancestors *"), ('Content-Security-Policy', "frame-ancestors 'none'")]
    assert detect(fa_page("default-src 'self'", **{}) if False else resp(
        headers=[('Content-Type', 'text/html')] + [(k, v) for k, v in GOOD.items()
                                                  if k not in ('Content-Security-Policy', 'X-Frame-Options')] + two)) == []


def test_frame_ancestors_findings_are_aggregated_and_serialized():
    pages = [resp(f'https://a.test/{i}', headers={**{k: v for k, v in GOOD.items() if k != 'Content-Security-Policy'},
                                                  'Content-Security-Policy': "frame-ancestors *"}) for i in range(3)]
    x = only(detect(*pages), 'HDR-FRAME-ANCESTORS-WEAK')
    assert len(x.affected_urls) == 3 and '3 pages are affected in total.' in x.evidence
    assert x.to_dict()['severity'] == 'Low' and x.reference.startswith('OWASP')


# ---------------------------------------------------------------- 4. unsafe-inline / strict-dynamic
@pytest.mark.parametrize('policy,weak,certain', [
    ("script-src 'unsafe-inline'", True, True),
    ("script-src 'unsafe-inline' 'strict-dynamic'", True, False),               # strict-dynamic alone: CSP3 only
    ("script-src 'strict-dynamic' 'unsafe-inline' https:", True, False),
    ("script-src 'unsafe-inline' 'nonce-abc123'", False, None),
    ("script-src 'unsafe-inline' 'nonce-Ab_c-d9=='", False, None),             # base64url alphabet and padding
    ("script-src 'unsafe-inline' 'sha256-AbC+/9=' ", False, None),
    ("script-src 'unsafe-inline' 'sha384-AbC' ", False, None),
    ("script-src 'unsafe-inline' 'sha512-AbC' ", False, None),
    ("script-src 'unsafe-inline' 'nonce-abc' 'strict-dynamic'", False, None),
    ("script-src 'unsafe-inline' 'sha256-abc=' 'strict-dynamic'", False, None),
    ("script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https: *", False, None),   # compatible pattern
    # invalid nonce/hash values do NOT neutralise unsafe-inline:
    ("script-src 'unsafe-inline' 'nonce-'", True, True),
    ("script-src 'unsafe-inline' 'nonce-!!!'", True, True),
    ("script-src 'unsafe-inline' 'nonce-abc", True, True),                      # unterminated quote
    ("script-src 'unsafe-inline' 'sha1-abc'", True, True),                      # sha1 is not a CSP hash algorithm
    ("script-src 'unsafe-inline' nonce-abc", True, True),                       # missing quotes: a host named nonce-abc
    ("script-src 'unsafe-inline' 'sha256-'", True, True),
    ("script-src 'unsafe-inline' 'nonce-a b'", True, True),
    ("script-src 'unsafe-inline' 'strict-dynamic' 'nonce-'", True, False),      # invalid nonce + strict-dynamic: still uncertain
    # strict-dynamic does not help the other weaknesses:
    ("script-src 'nonce-abc' 'strict-dynamic' 'unsafe-eval'", True, True),
    ("script-src 'nonce-abc' https:", True, True),                              # no strict-dynamic: scheme still allows scripts
    ("script-src 'nonce-abc' *", True, True),
    ("script-src 'strict-dynamic' *", True, False),                             # no nonce/hash: host sources only ignored by CSP3
    ("script-src 'strict-dynamic' https:", True, False),
])
def test_unsafe_inline_and_strict_dynamic_logic(policy, weak, certain):
    from scanner.detectors.security_headers import _script_weaknesses
    (parsed,) = parse_csp([policy])
    details = _script_weaknesses(parsed)
    assert bool(details) is weak
    if weak:
        assert any(c for _r, c in details) is certain


def test_strict_dynamic_alone_is_reported_with_potential_confidence():
    f = detect(resp(headers={**GOOD, 'Content-Security-Policy': "script-src 'strict-dynamic' 'unsafe-inline'"}))
    x = only(f, 'HDR-CSP-UNSAFE')
    assert x.confidence == 'Potential' and x.severity == 'Low' and 'CSP3' in x.evidence
    plain = only(detect(resp(headers={**GOOD, 'Content-Security-Policy': "script-src 'unsafe-inline'"})), 'HDR-CSP-UNSAFE')
    assert plain.confidence == 'Confirmed' and 'CSP3' not in plain.evidence


def test_finding_is_confirmed_if_any_page_is_confirmed_and_policies_combine_conservatively():
    uncertain = resp('https://a.test/1', headers={**GOOD, 'Content-Security-Policy': "script-src 'strict-dynamic' 'unsafe-inline'"})
    certain = resp('https://a.test/2', headers={**GOOD, 'Content-Security-Policy': "script-src 'unsafe-inline'"})
    assert only(detect(uncertain, certain), 'HDR-CSP-UNSAFE').confidence == 'Confirmed'
    assert only(detect(uncertain), 'HDR-CSP-UNSAFE').confidence == 'Potential'
    # two policies: one certainly weak, one weak only for old browsers -> overall not certain
    both = resp(headers={**GOOD, 'Content-Security-Policy': "script-src 'unsafe-inline', script-src 'strict-dynamic' 'unsafe-inline'"})
    assert only(detect(both), 'HDR-CSP-UNSAFE').confidence == 'Potential'


def test_nonce_secret_values_are_still_redacted_with_strict_dynamic():
    f = detect(resp(headers={**GOOD, 'Content-Security-Policy': "script-src 'nonce-TOPSECRET' 'strict-dynamic' 'unsafe-eval'"}))
    assert 'TOPSECRET' not in ' '.join(x.evidence for x in f)


# ---------------------------------------------------------------- 5. internal identity vs display
def test_pages_differing_only_by_query_value_stay_distinct_internally():
    a, b = 'https://a.test/p?id=1&sig=SECRETONE', 'https://a.test/p?id=2&sig=SECRETTWO'
    x = only(detect(resp(a), resp(b)), 'HDR-CSP-MISSING')
    assert x.affected_urls == [a, b]                                      # internal identity: both pages, unmasked
    assert '2 pages are affected in total.' in x.evidence
    assert x.display_urls == ['https://a.test/p?id=[redacted]&sig=[redacted]'] * 2      # display: still two entries
    d = x.to_dict()
    assert len(d['affected_urls']) == 2 and d['affected_urls'] == x.display_urls
    assert not any(s in json.dumps(d) for s in ('SECRETONE', 'SECRETTWO', 'id=1', 'id=2'))


def test_url_scope_fingerprints_distinguish_pages_that_differ_only_by_query_value():
    from scanner.rules import build_finding
    f1 = build_finding('INFO-VERBOSE-ERROR', ['https://a.test/p?id=1'], 'ev')
    f2 = build_finding('INFO-VERBOSE-ERROR', ['https://a.test/p?id=2'], 'ev')
    f3 = build_finding('INFO-VERBOSE-ERROR', ['https://a.test/p?id=1'], 'ev')
    assert f1.dedupe_scope == 'url'
    assert f1.fingerprint() != f2.fingerprint() and f1.fingerprint() == f3.fingerprint()
    assert len(dedupe([f1, f2, f3])) == 2                                  # the two real pages are NOT merged
    assert f1.to_dict()['fingerprint'] != f2.to_dict()['fingerprint']
    assert f1.to_dict()['affected_urls'] == f2.to_dict()['affected_urls']   # display text alone would be identical


def test_host_scope_dedupe_keeps_every_distinct_url():
    from scanner.rules import build_finding
    f1 = build_finding('HDR-CSP-MISSING', ['https://a.test/p?id=1'], 'ev')
    f2 = build_finding('HDR-CSP-MISSING', ['https://a.test/p?id=2'], 'ev')
    (merged,) = dedupe([f1, f2])
    assert merged.affected_urls == ['https://a.test/p?id=1', 'https://a.test/p?id=2']
    assert len(merged.to_dict()['affected_urls']) == 2


def test_engine_keeps_pages_that_differ_only_by_query_and_masks_them_in_output(make_server, engine):
    H = {'Content-Type': 'text/html'}
    srv = make_server({'/': (200, H, b'<a href="/p?id=1&sig=AAA1">a</a><a href="/p?id=2&sig=BBB2">b</a>'),
                       '/p': (200, H, b'x')})
    out = engine.run(srv.base + '/', True, SH)
    f = next(x for x in out.findings if x.extra['rule'] == 'HDR-CSP-MISSING')
    assert len(f.affected_urls) == 3 and sum('/p?' in u for u in f.affected_urls) == 2
    d = f.to_dict()
    assert len(d['affected_urls']) == 3 and '3 pages are affected in total.' in d['evidence']
    assert not any(s in json.dumps(d) for s in ('AAA1', 'BBB2', 'sig=A', 'sig=B'))


def test_finding_repr_does_not_expose_internal_urls():
    x = only(detect(resp(SECRET_URL)), 'HDR-CSP-MISSING')
    assert not any(leak in repr(x) for leak in LEAKS)


# ---------------------------------------------------------------- 6. malformed CSP header
MALFORMED = ['', '   ', ';;;', ',,,', ';,;,', 'garbage', 'foo bar baz', 'x' * 1000, 'not-a-directive value; also-not value',
             "'nonce-HEADERSECRET' junk"]


@pytest.mark.parametrize('value', MALFORMED)
def test_present_but_malformed_csp_header_is_not_reported_as_absent(value):
    f = detect(resp(headers={**{k: v for k, v in GOOD.items() if k != 'Content-Security-Policy'},
                             'Content-Security-Policy': value}))
    x = only(f, 'HDR-CSP-MALFORMED')
    assert 'HDR-CSP-MISSING' not in rules(f)
    assert 'sent a Content-Security-Policy header' in x.evidence and 'without a Content-Security-Policy header' not in x.evidence
    assert x.severity == 'Medium' and x.confidence == 'Confirmed' and 'HEADERSECRET' not in x.evidence


def test_absent_valid_and_malformed_csp_are_three_distinct_outcomes():
    base = {k: v for k, v in GOOD.items() if k != 'Content-Security-Policy'}
    absent = detect(resp(headers=base))
    valid = detect(resp(headers={**base, 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"}))
    malformed = detect(resp(headers={**base, 'Content-Security-Policy': 'garbage'}))
    assert rules(absent) == {'HDR-CSP-MISSING'} and valid == [] and rules(malformed) == {'HDR-CSP-MALFORMED'}
    assert 'without a Content-Security-Policy header' in only(absent, 'HDR-CSP-MISSING').evidence


@pytest.mark.parametrize('policy', ["default-src", "script-src", "upgrade-insecure-requests", "sandbox",
                                    "default-src 'self', garbage", "garbage; default-src 'self'"])
def test_headers_with_at_least_one_recognised_directive_are_not_malformed(policy):
    f = detect(resp(headers={**GOOD, 'Content-Security-Policy': policy + "; frame-ancestors 'none'"}))
    assert not {'HDR-CSP-MALFORMED', 'HDR-CSP-MISSING'} & rules(f)


def test_malformed_header_with_an_early_meta_csp_is_worded_precisely():
    f = detect(meta_page("default-src 'self'", headers={'Content-Security-Policy': 'garbage'}))
    assert {'HDR-CSP-MALFORMED', 'HDR-CSP-META-ONLY'} <= rules(f) and 'HDR-CSP-MISSING' not in rules(f)
    ev = only(f, 'HDR-CSP-META-ONLY').evidence
    assert 'sent a Content-Security-Policy header with no valid policy' in ev and 'sent no Content-Security-Policy header' not in ev


def test_malformed_header_with_a_late_meta_csp_is_worded_precisely():
    f = detect(doc('<script src=a.js></script>' + CSP_META, headers={'Content-Security-Policy': ''}))
    assert {'HDR-CSP-MALFORMED', 'HDR-CSP-META-LATE'} <= rules(f)
    assert 'sent a Content-Security-Policy header with no valid policy' in only(f, 'HDR-CSP-META-LATE').evidence


def test_malformed_header_alongside_report_only():
    f = detect(resp(headers={'Content-Security-Policy': 'garbage',
                             'Content-Security-Policy-Report-Only': "default-src 'self'"}))
    assert {'HDR-CSP-MALFORMED', 'HDR-CSP-REPORT-ONLY'} <= rules(f) and 'HDR-CSP-MISSING' not in rules(f)


def test_garbage_meta_csp_is_reported_as_missing_with_an_explanation():
    f = detect(meta_page('this is not a policy'))
    assert 'contains no usable policy' in only(f, 'HDR-CSP-MISSING').evidence
    assert not {'HDR-CSP-META-ONLY', 'HDR-CSP-META-LATE'} & rules(f)


def test_malformed_csp_findings_are_aggregated_and_serialize_cleanly():
    pages = [resp(f'https://a.test/{i}', headers={**GOOD, 'Content-Security-Policy': 'garbage'}) for i in range(3)]
    x = only(detect(*pages), 'HDR-CSP-MALFORMED')
    assert len(x.affected_urls) == 3 and json.dumps(x.to_dict())


# ---------------------------------------------------------------- 7. HSTS evidence ranking
def hsts_values_in_order(evidence):
    out = []
    for m in re.finditer(r'Strict-Transport-Security(?: max-age=(\d+)|: "[^"]*" which is not valid HSTS)', evidence):
        out.append(int(m.group(1)) if m.group(1) is not None else 'invalid')
    return out


def test_different_max_age_values_never_tie():
    for pages_order in ((200, 100), (100, 200)):
        x = only(detect(*[hsts_page(i, f'max-age={v}') for i, v in enumerate(pages_order)]), 'HDR-HSTS-WEAK')
        assert hsts_values_in_order(x.evidence) == [100, 200]       # shorter first, whichever page came first
    x = only(detect(*[hsts_page(i, f'max-age={v}') for i, v in enumerate((9_000_000, 9_000_001, 8_999_999))]), 'HDR-HSTS-WEAK')
    assert hsts_values_in_order(x.evidence) == [8_999_999, 9_000_000, 9_000_001]      # one-second differences still order


def test_hsts_ranking_is_deterministic_for_every_page_order():
    import itertools
    values = ['max-age=5000', 'max-age=1000', 'max-age=0', 'max-age=notanumber', 'max-age=3000', 'max-age=2000']
    shown = set()
    for perm in itertools.islice(itertools.permutations(range(len(values))), 0, 720, 7):
        x = only(detect(*[hsts_page(i, values[j]) for i, j in enumerate(perm)]), 'HDR-HSTS-WEAK')
        shown.add(tuple(hsts_values_in_order(x.evidence)))
        assert hsts_values_in_order(x.evidence) == [0, 'invalid', 1000]       # worst first, always the same three
        assert '3 other distinct configuration(s)' in x.evidence
    assert len(shown) == 1


def test_most_severe_hsts_configuration_is_first_even_when_it_arrives_last():
    pages = [hsts_page(i, f'max-age={v}') for i, v in enumerate((50, 40, 30, 20))] + [hsts_page(9, 'max-age=0')]
    assert hsts_values_in_order(only(detect(*pages), 'HDR-HSTS-WEAK').evidence)[0] == 0


def test_collector_accepts_tuple_weights_with_eviction():
    from scanner.detectors.security_headers import _Collector
    c = _Collector()
    for i in range(_Collector.MAX_TRACKED + 20):
        c.add('HDR-HSTS-WEAK', f'https://a.test/{i}', f'ev{i}', variant=i, weight=(1, -(i + 1)))
    c.add('HDR-HSTS-WEAK', 'https://a.test/z', 'zero', variant='z', weight=(3, 0))
    kept = {v[2] for v in c.items['HDR-HSTS-WEAK']['variants'].values()}
    assert 'zero' in kept and len(kept) <= _Collector.MAX_TRACKED


# ---------------------------------------------------------------- 9. HSTS syntax
@pytest.mark.parametrize('value,max_age', [
    ('max-age=31536000', 31536000), ('MAX-AGE=10', 10), ('Max-Age=10; IncludeSubDomains', 10),
    ('max-age="31536000"', 31536000),                          # double-quoted value: valid (RFC 6797 quoted-string)
    ('max-age="31536000"; includeSubDomains; preload', 31536000),
    (r'max-age="1\0"', 10),                                     # quoted-pair is unescaped
    ('max-age = 10', 10),                                       # whitespace around "=" tolerated (documented)
    ('max-age=10;;preload', 10), ('max-age=10; foo=bar', 10), ('max-age=10; foo="x y"', 10),
    ('max-age=99999999999999999999', 99999999999999999999),
    ("max-age='31536000'", None),                               # single quotes are not HTTP quoting
    ('max-age="31536000', None), ('max-age=31536000"', None), ('max-age=""', None),
    ('max-age=10; max-age=20', None), ('MAX-AGE=10; max-age=20', None),            # duplicate directive: header rejected
    ('max-age=10; includeSubDomains; includeSubDomains', None),
    ('max-age=10; includeSubDomains=true', None),                                   # valued includeSubDomains: rejected
    ('includeSubDomains', None), ('max-age', None), ('max-age=', None), ('', None), (None, None), (';;;', None),
    ('max-age=-5', None), ('max-age=+5', None), ('max-age=1.5', None), ('max-age=10abc', None), ('max-age=1 0', None),
    ('max-age=١٢٣', None),                      # Arabic-Indic digits are not ASCII digits
    ('max-age=²', None),                                   # superscript two: str.isdigit() is True, int() would raise
    ('max-age=10; bad name=x', None),
])
def test_parse_hsts_max_age_syntax(value, max_age):
    assert parse_hsts_max_age(value) == max_age


@pytest.mark.parametrize('value,expect', [
    ('max-age=31536000', None), ('max-age="31536000"', None),                      # quoted and unquoted both fine
    ("max-age='31536000'", 'invalid'), ('max-age=10; max-age=20', 'invalid'), ('max-age=²', 'invalid'),
    ('max-age="60"', 'weak'), ('max-age=60', 'weak'),
])
def test_hsts_header_outcomes_for_quoted_and_unquoted_values(value, expect):
    f = detect(resp(headers={**GOOD, 'Strict-Transport-Security': value}))
    if expect is None:
        assert detect(resp(headers={**GOOD, 'Strict-Transport-Security': value})) == []
    elif expect == 'invalid':
        assert 'not valid HSTS' in only(f, 'HDR-HSTS-WEAK').evidence
    else:
        assert 'below the' in only(f, 'HDR-HSTS-WEAK').evidence


def test_unicode_digit_hsts_value_cannot_hide_the_page_from_other_checks():
    f = detect(resp(headers={'Strict-Transport-Security': 'max-age=²'}))        # used to raise inside int()
    assert 'HDR-HSTS-WEAK' in rules(f) and 'HDR-CSP-MISSING' in rules(f)


def test_engine_judges_hsts_on_non_html_https_responses(make_server, engine, make_cert):
    """
    The lab server's certificate is self-signed, so (Phase 2 behaviour, unchanged) the crawler reads only the
    start page, via its documented verify_tls=False fallback. The start page is a JSON endpoint here.
    """
    srv = make_server({'/': (200, {'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff'},
                             b'{"ok": true}')}, tls=make_cert('lab.test', 'lab.test'))
    out = engine.run(srv.base + '/', True, SH)
    assert out.pages_crawled == 1 and len(srv.seen) == 1
    assert {f.extra['rule'] for f in out.findings} == {'HDR-HSTS-MISSING'}           # JSON is judged; document headers are not
    srv.routes['/'] = (200, {'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff',
                             'Strict-Transport-Security': 'max-age=0'}, b'{"ok": true}')
    weak = engine.run(srv.base + '/', True, SH)
    assert {f.extra['rule'] for f in weak.findings} == {'HDR-HSTS-WEAK'} and 'switches HSTS off' in weak.findings[0].evidence
