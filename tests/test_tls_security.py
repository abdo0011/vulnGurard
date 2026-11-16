"""
Feature 3: SSL/TLS detection, detector and plumbing tests.

The detector is exercised on hand-built inputs to pin every error-number mapping and every "no evidence, no finding"
case. Real HTTPS handshakes (certificates generated with `cryptography`) are in test_tls_handshakes.py, so this module
has no optional dependency and is never skipped.
"""
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.crawler import CrawlResult, Page
from scanner.detectors import CATEGORIES, get_detectors
from scanner.detectors.tls_security import MAX_FAILURES, TlsSecurityDetector
from scanner.http_client import FetchError, HttpResponse, ScanHTTPClient
from scanner.rules import get_rule

ROOT = Path(__file__).resolve().parent.parent
TLS = {'ssl_tls'}


# ---------------------------------------------------------------- helpers
def resp(url='https://a.test/', version='TLSv1.3', scheme='https'):
    return HttpResponse(url=url, method='GET', status=200, reason='', headers=[('Content-Type', 'text/html')], body=b'<p>x</p>',
                        truncated=False, ip='93.184.216.34', scheme=scheme, tls_version=version)


def detect(pages=(), failures=(), client=None, crawl_result='auto'):
    if crawl_result == 'auto':
        crawl_result = SimpleNamespace(tls_failures=list(failures))
    context = SimpleNamespace(pages=[Page(r.url, 0, r) for r in pages], client=client, crawl_result=crawl_result, target=None, config=None)
    return TlsSecurityDetector().run(context)


def rules(found):
    return {f.extra['rule'] for f in found}


def only(found, rule):
    (f,) = [x for x in found if x.extra['rule'] == rule]
    return f


class ForbiddenClient:
    """Any use of the client (i.e. any network access) fails the test."""
    def __getattr__(self, name):
        raise AssertionError(f'the TLS detector must not touch the client ({name})')


# ---------------------------------------------------------------- protocol versions
@pytest.mark.parametrize('version', ['TLSv1.3', 'TLSv1.2'])
def test_modern_tls_is_only_the_untested_legacy_note(version):
    found = detect([resp(version=version)])
    assert rules(found) == {'TLS-LEGACY-UNTESTED'}
    f = found[0]
    assert f.confidence == 'Informational' and f.severity == 'Informational'
    assert version in f.evidence and 'not evidence that the server is secure' in f.evidence


@pytest.mark.parametrize('version', ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'])
def test_an_obsolete_negotiated_version_is_a_confirmed_finding(version):
    found = detect([resp(version=version)])
    assert rules(found) == {'TLS-PROTOCOL-OBSOLETE'}                       # and no "untested" note for the same host
    f = found[0]
    assert f.confidence == 'Confirmed' and f.severity == 'Medium' and version in f.evidence


@pytest.mark.parametrize('version,note,cited,not_cited', [
    ('TLSv1', 'TLS 1.0, deprecated by RFC 8996', 'RFC 8996', ('RFC 7568', 'RFC 6176')),
    ('TLSv1.1', 'TLS 1.1, deprecated by RFC 8996', 'RFC 8996', ('RFC 7568', 'RFC 6176')),
    ('SSLv3', 'SSL 3.0, prohibited by RFC 7568', 'RFC 7568', ('RFC 8996', 'RFC 6176')),
    ('SSLv2', 'SSL 2.0, prohibited by RFC 6176', 'RFC 6176', ('RFC 8996', 'RFC 7568'))])
def test_each_obsolete_version_is_cited_against_the_rfc_that_covers_it(version, note, cited, not_cited):
    """RFC 8996 deprecates TLS 1.0 and 1.1 only; SSLv3 is RFC 7568 and SSLv2 is RFC 6176."""
    f = detect([resp(version=version)])[0]
    assert f.extra['rule'] == 'TLS-PROTOCOL-OBSOLETE' and f'using {version} ({note})' in f.evidence and cited in f.evidence
    assert not any(other in f.evidence for other in not_cited)
    assert 'RFC 8996' not in f.evidence or version in ('TLSv1', 'TLSv1.1')


def test_the_catalog_description_covers_all_four_obsolete_protocols_with_the_correct_rfcs():
    import re
    from scanner.detectors.tls_security import _OBSOLETE_NOTE
    r = get_rule('TLS-PROTOCOL-OBSOLETE')
    text = ' '.join(r.description.split())
    assert re.search(r'TLS 1\.0 or TLS 1\.1 \(deprecated by RFC 8996\)', text)
    assert re.search(r'SSL 3\.0 \(prohibited by RFC 7568\)', text)
    assert re.search(r'SSL 2\.0 \(prohibited by RFC 6176\)', text)
    assert text.count('RFC 8996') == 1 and text.count('RFC 7568') == 1 and text.count('RFC 6176') == 1
    assert not re.search(r'SS[Ll][^()]*RFC 8996|SSL [23]\.0 \(deprecated', text)                 # 8996 is never attached to SSL
    for note in _OBSOLETE_NOTE.values():                                                          # same wording as the finding evidence
        protocol, _, rfc = note.partition(', ')
        assert protocol in text and rfc.split(' by ')[-1] in text
    # the rest of the rule is unchanged
    assert (r.id, r.title, r.category, r.impact, r.likelihood, r.dedupe_scope) == (
        'TLS-PROTOCOL-OBSOLETE', 'Obsolete TLS protocol version accepted', 'ssl_tls', 'Medium', 'Medium', 'host')
    assert r.reference == 'OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security)'
    assert r.method == 'Safe probe: standard TLS handshake (no attack traffic)'
    assert r.impact_text == 'These versions have known weaknesses and fail modern compliance baselines (e.g. PCI DSS).'
    assert r.remediation == 'Disable SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1; support TLS 1.2 and 1.3 only.'
    assert all(name in r.remediation for name in ('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'))


def test_a_finding_built_from_the_rule_keeps_severity_and_category():
    f = detect([resp(version='SSLv3')])[0]
    assert (f.rule_id, f.category, f.severity, f.confidence) == ('TLS-PROTOCOL-OBSOLETE', 'ssl_tls', 'Medium', 'Confirmed')
    assert 'SSL 3.0, prohibited by RFC 7568' in f.evidence and 'RFC 8996' not in f.evidence


def test_all_four_obsolete_versions_remain_detectable_and_only_those():
    for version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
        assert rules(detect([resp(version=version)])) == {'TLS-PROTOCOL-OBSOLETE'}, version
    for version in ('TLSv1.2', 'TLSv1.3'):
        assert 'TLS-PROTOCOL-OBSOLETE' not in rules(detect([resp(version=version)]))


@pytest.mark.parametrize('version', [None, '', 'unknown', 'TLSv9', 13, b'TLSv1', ['TLSv1']])
def test_missing_or_unrecognised_version_metadata_yields_nothing(version):
    assert detect([resp(version=version)]) == []


def test_plain_http_responses_are_never_judged_for_tls():
    assert detect([resp('http://a.test/', version='TLSv1', scheme='http')]) == []
    assert detect([resp('http://a.test/', version='TLSv1.3', scheme='http')]) == []


def test_obsolete_evidence_on_one_host_does_not_hide_a_modern_host():
    found = detect([resp('https://old.test/', 'TLSv1'), resp('https://new.test/', 'TLSv1.3')])
    assert {(f.extra['rule'], f.extra['host']) for f in found} == {('TLS-PROTOCOL-OBSOLETE', 'old.test'), ('TLS-LEGACY-UNTESTED', 'new.test')}


def test_findings_are_aggregated_per_host_and_port():
    found = detect([resp('https://a.test/a?x=1', 'TLSv1.1'), resp('https://a.test/b', 'TLSv1.1'), resp('https://a.test:8443/', 'TLSv1.1')])
    assert len(found) == 2
    two = [f for f in found if len(f.affected_urls) == 2][0]
    assert '2 requests to this host:port' in two.evidence


# ---------------------------------------------------------------- certificate failures
@pytest.mark.parametrize('code,rule,confidence,severity', [
    (10, 'TLS-CERT-EXPIRED', 'Confirmed', 'High'),
    (9, 'TLS-CERT-NOT-YET-VALID', 'Confirmed', 'Medium'),
    (62, 'TLS-CERT-HOSTNAME-MISMATCH', 'Confirmed', 'High'),
    (64, 'TLS-CERT-HOSTNAME-MISMATCH', 'Confirmed', 'High'),
    (18, 'TLS-CERT-SELF-SIGNED', 'Confirmed', 'High'),
    (19, 'TLS-CERT-UNTRUSTED', 'Potential', 'Medium'),
    (20, 'TLS-CERT-UNTRUSTED', 'Potential', 'Medium'),
    (21, 'TLS-CERT-UNTRUSTED', 'Potential', 'Medium'),
    (2, 'TLS-CERT-UNTRUSTED', 'Potential', 'Medium')])
def test_verifier_error_numbers_map_to_the_specific_rule(code, rule, confidence, severity):
    found = detect(failures=[('https://a.test/', code, 'whatever OpenSSL said')])
    assert rules(found) == {rule}
    f = found[0]
    assert f.confidence == confidence and f.severity == severity
    assert f'OpenSSL verification error {code}' in f.evidence and "host 'a.test'" in f.evidence
    assert 'first problem' in f.evidence                                    # the masking caveat is always stated


@pytest.mark.parametrize('code,reports', [
    (2, 'OpenSSL could not obtain the issuer certificate'),
    (19, 'OpenSSL reports a self-signed certificate in the certificate chain'),
    (20, 'OpenSSL could not find the issuer certificate'),
    (21, 'OpenSSL could not verify the first certificate')])
def test_chain_errors_say_what_openssl_reports_and_hedge_the_cause(code, reports):
    """They are issuer / chain-validation problems; OpenSSL does not say whether the server or the trust store is at fault."""
    f = detect(failures=[('https://a.test/', code, '')])[0]
    assert f.extra['rule'] == 'TLS-CERT-UNTRUSTED' and f.confidence == 'Potential'
    assert reports in f.evidence and "scanner host's trust store" in f.evidence
    cause_claims = [p for p in ('the server is misconfigured', 'is misconfigured', 'is a man-in-the-middle', 'attacker', 'forged', 'invalid issuer',
                                'the server sent an incomplete chain', 'the server does not send') if p in f.evidence.lower()]
    assert cause_claims == []
    if code in (20, 21):
        assert any(w in f.evidence for w in ('may be', 'commonly'))                          # the likely cause is hedged, never asserted


def test_error_19_does_not_claim_a_private_root_or_a_misconfiguration():
    f = detect(failures=[('https://a.test/', 19, '')])[0]
    assert 'does not by itself show' in f.evidence and 'private root or a misconfiguration' in f.evidence


def test_trust_verdicts_state_that_they_come_from_the_scanner_hosts_trust_store():
    assert "scanner host's trust store" in detect(failures=[('https://a.test/', 20, '')])[0].evidence
    assert "trust store" not in detect(failures=[('https://a.test/', 10, '')])[0].evidence          # intrinsic problems: no caveat


@pytest.mark.parametrize('code', [7, 23, 26, 999, -1, 0])
def test_any_other_verifier_error_is_reported_as_invalid_with_openssls_message(code):
    f = detect(failures=[('https://a.test/', code, 'unsupported certificate purpose')])[0]
    assert f.extra['rule'] == 'TLS-CERT-INVALID' and f.confidence == 'Confirmed'
    assert f'verification error {code}' in f.evidence and 'unsupported certificate purpose' in f.evidence


@pytest.mark.parametrize('code', [None, 'ten', 10.0, True, [10]])
def test_unknown_or_malformed_error_numbers_are_never_mapped_to_a_specific_cause(code):
    f = detect(failures=[('https://a.test/', code, None)])[0]
    assert f.extra['rule'] == 'TLS-CERT-INVALID' and 'verification error number not available' in f.evidence


def test_the_message_is_bounded_and_reduced_to_printable_ascii():
    f = detect(failures=[('https://a.test/', 7, 'bad\x00\r\n\u202e' + 'x' * 5000)])[0]
    assert '\x00' not in f.evidence and '\u202e' not in f.evidence and '\n' not in f.evidence and len(f.evidence) < 800


@pytest.mark.parametrize('record', [None, (), ('https://a.test/',), ('https://a.test/', 10), (None, 10, ''), (5, 10, ''),
                                    ('', 10, ''), ('not a url', 10, ''), ('https://', 10, ''), 'https://a.test/', 42,
                                    ('https://a.test/', 10, '', 'extra')])
def test_malformed_failure_records_produce_no_finding_and_no_error(record):
    assert detect(failures=[record]) == []


@pytest.mark.parametrize('crawl_result', [None, SimpleNamespace(), SimpleNamespace(tls_failures=None), SimpleNamespace(tls_failures=[])])
def test_missing_crawl_metadata_produces_no_finding(crawl_result):
    assert detect(crawl_result=crawl_result) == []
    assert detect([resp()], crawl_result=crawl_result) and rules(detect([resp()], crawl_result=crawl_result)) == {'TLS-LEGACY-UNTESTED'}


def test_a_page_without_any_tls_evidence_is_not_a_finding():
    assert detect([resp(version=None)]) == [] and detect([]) == []


def test_failures_are_aggregated_per_rule_and_host_and_bounded():
    found = detect(failures=[(f'https://a.test/p{i}', 10, '') for i in range(5)] + [('https://b.test/', 10, '')])
    assert {(f.extra['host'], len(f.affected_urls)) for f in found} == {('a.test', 5), ('b.test', 1)}
    many = detect(failures=[(f'https://h{i}.test/', 10, '') for i in range(MAX_FAILURES + 50)])
    assert len(many) == MAX_FAILURES


def test_two_different_problems_on_one_host_are_two_findings():
    assert rules(detect(failures=[('https://a.test/', 10, ''), ('https://a.test/x', 62, '')])) == {'TLS-CERT-EXPIRED', 'TLS-CERT-HOSTNAME-MISMATCH'}


def test_findings_use_the_existing_model_and_catalog():
    found = detect([resp('https://a.test/', 'TLSv1')], [('https://a.test/', 10, '')])
    assert all(f.category == 'ssl_tls' and f.reference and f.remediation and f.impact for f in found)
    assert all(f.rule_id == f.extra['rule'] for f in found)                       # no per-instance suffix: one per host
    assert {f.fingerprint() for f in found} == {f.fingerprint() for f in detect([resp('https://a.test/x', 'TLSv1')], [('https://a.test/y', 10, '')])}


# ---------------------------------------------------------------- no leakage
def test_evidence_never_contains_urls_query_values_ips_or_certificate_fields():
    raw = 'https://user:PASSSECRET@a.test:8443/p?token=QUERYSECRET&sig=TOKSEC#frag'
    found = detect([resp(raw, 'TLSv1')], [(raw, 62, 'Hostname mismatch, certificate is not valid for a.test')])
    blob = ' '.join(f'{f.evidence} {f.description} {f.impact}' for f in found) + json.dumps([f.to_dict() for f in found]) + repr(found)
    for secret in ('PASSSECRET', 'QUERYSECRET', 'TOKSEC', '93.184.216.34', 'frag'):
        assert secret not in blob, secret
    evidence = ' '.join(f.evidence for f in found).lower()
    for word in ('subject', 'issuer', 'serial', 'fingerprint', 'begin certificate', 'private key'):
        assert word not in evidence, word


# ---------------------------------------------------------------- URL validation and credential safety
import dataclasses  # noqa: E402

CREDENTIAL_URLS = ['https://alice:PASSSECRET@a.test/p?x=1', 'https://PASSSECRET@a.test/p?x=1', 'https://alice:@a.test/p?x=1',
                   'https://:PASSSECRET@a.test/p?x=1', 'HTTPS://Alice:PassSecret@A.TEST/p?x=1',
                   'https://alice:PASSSECRET@a.test:443/p?x=1', 'https://al%40ice:PASSSECRET%3A@a.test/p?x=1']


def every_output(findings):
    """Everything a finding exposes, including the internals (extra, raw affected_urls, dataclass fields, fingerprint input)."""
    parts = []
    for f in findings:
        parts += [repr(f), str(f), f'{f}', f'{f!r}', json.dumps(f.to_dict()), json.dumps(f.extra), repr(f.extra),
                  json.dumps(dataclasses.asdict(f)), repr(vars(f)), f.evidence, f.description, f.impact, f.remediation, f.title,
                  repr(f.affected_urls), repr(f.display_urls), f.fingerprint()]
    return '\n'.join(parts)


@pytest.mark.parametrize('url', CREDENTIAL_URLS)
def test_credentials_never_appear_in_any_certificate_finding_output(url):
    found = detect(failures=[(url, 10, 'm')])
    assert rules(found) == {'TLS-CERT-EXPIRED'}
    blob = every_output(found)
    for secret in ('PASSSECRET', 'passsecret', 'alice', 'Alice', 'al%40ice', 'PassSecret'):
        assert secret not in blob, secret
    assert found[0].extra['host'] == 'a.test' and found[0].affected_urls == [found[0].affected_urls[0]]
    assert '@' not in found[0].extra['host'] and '@' not in found[0].affected_urls[0]


@pytest.mark.parametrize('url', CREDENTIAL_URLS)
@pytest.mark.parametrize('version', ['TLSv1', 'TLSv1.3'])
def test_credentials_never_appear_in_any_protocol_finding_output(url, version):
    found = detect([resp(url, version)])
    assert found and 'PASSSECRET' not in every_output(found).replace('PassSecret', 'PASSSECRET').replace('passsecret', 'PASSSECRET')
    blob = every_output(found).lower()
    assert 'alice' not in blob and 'passsecret' not in blob and found[0].extra['host'] == 'a.test'


def test_different_credentials_for_the_same_endpoint_share_one_grouping_key_and_one_finding():
    found = detect(failures=[(u, 10, '') for u in CREDENTIAL_URLS] + [('https://a.test/p?x=1', 10, ''), ('https://other:pw@a.test/zzz', 10, '')])
    assert len(found) == 1 and found[0].extra['host'] == 'a.test'
    assert found[0].fingerprint() == detect(failures=[('https://a.test/', 10, '')])[0].fingerprint()
    assert len({f.fingerprint() for f in [detect(failures=[(u, 10, '')])[0] for u in CREDENTIAL_URLS]}) == 1
    assert len(detect([resp(u, 'TLSv1') for u in CREDENTIAL_URLS])) == 1


def test_the_same_host_with_a_different_port_is_a_different_endpoint():
    found = detect(failures=[('https://u:p@a.test:8443/', 10, ''), ('https://a.test/', 10, ''), ('https://x@a.test:9443/', 10, '')])
    assert sorted(f.extra['host'] for f in found) == ['a.test', 'a.test:8443', 'a.test:9443']


@pytest.mark.parametrize('url,key,label', [
    ('https://a.test/', 'a.test', "host 'a.test'"),
    ('https://a.test:443/', 'a.test', "host 'a.test'"),                         # the default HTTPS port is the same endpoint
    ('https://a.test:8443/', 'a.test:8443', "host 'a.test:8443'"),
    ('HTTPS://A.TEST./x', 'a.test', "host 'a.test'"),                         # scheme and host are case-insensitive; a trailing dot is dropped
    ('https://192.0.2.10/', '192.0.2.10', "host '192.0.2.10'"),
    ('https://192.0.2.10:8443/', '192.0.2.10:8443', "host '192.0.2.10:8443'"),
    ('https://u:p@192.0.2.10:443/', '192.0.2.10', "host '192.0.2.10'"),
    ('https://[::1]/', '[::1]', "host '[::1]'"),
    ('https://[::1]:443/', '[::1]', "host '[::1]'"),
    ('https://[::1]:8443/', '[::1]:8443', "host '[::1]:8443'"),
    ('https://[2001:DB8:0:0:0:0:0:1]:8443/', '[2001:db8::1]:8443', "host '[2001:db8::1]:8443'"),
    ('https://u:p@[2001:db8::1]/', '[2001:db8::1]', "host '[2001:db8::1]'"),
    ('https://lab-host-1.example.test:65535/', 'lab-host-1.example.test:65535', "host 'lab-host-1.example.test:65535'")])
def test_endpoint_keys_are_canonical_for_ipv4_ipv6_names_and_ports(url, key, label):
    found = detect(failures=[(url, 62, '')])
    assert len(found) == 1 and found[0].extra['host'] == key and label in found[0].evidence
    assert found[0].extra['host'] == detect([resp(url, 'TLSv1.3')])[0].extra['host']       # the protocol path agrees
    assert found[0].fingerprint() == detect(failures=[(url.replace('u:p@', ''), 62, '')])[0].fingerprint()


INVALID_URLS = ['https://a.test:/x', 'https://a.test:', 'https://a.test:?q=1', 'https://a.test:#f', 'https://u:p@a.test:/x', 'https://[::1]:/x',
                'https://[::1]:', 'https://192.0.2.1:/', 'HTTPS://A.TEST:/x', 'http://a.test:/', 'HTTP://a.test/', 'ftp://a.test/', 'javascript://a.test/', 'javascript:alert(1)', 'data:text/html,x',
                'file:///etc/passwd', 'ws://a.test/', 'wss://a.test/', 'mailto:a@a.test', '//a.test/', '///a.test', 'a.test/', 'a.test', '/path', '?q=1',
                '', ' ', 'https:', 'https://', 'https:///path', 'https://:443/', 'https://u:p@/', 'https://@/', 'https://a.test:99999/',
                'https://a.test:65536/', 'https://a.test:0/', 'https://a.test:abc/', 'https://a.test:-1/', 'https://a.test:443:443/', 'https://a.test:/x'[:0] + 'https://a.test:80:90/',
                'https://[::1/', 'https://[::1]x/', 'https://[::1]:abc/', 'https://[fe80::1%25eth0]/', 'https://[not-an-ip]/', 'https://[1:2:3]/',
                'https://a b.test/', ' https://a.test/', 'https://a.test/ ', 'https://a.test\\@evil.test/', 'https://a.test\\evil.test/',
                'https://-a.test/', 'https://a-.test/', 'https://a..test/', 'https://.a.test/', 'https://a.test../', 'https://a$b.test/',
                'https://ex\u00e4mple.test/', 'https://\u202ea.test/', 'https://a.test/\x00', 'https://a.test/\n', 'https://a.test/\r\nHost: x',
                'https://' + 'a' * 64 + '.test/', 'https://' + '.'.join(['a' * 60] * 5) + '/', 'https://a.test/' + 'x' * 3000, 'https://256.256.256.256.256/',
                'https:a.test', 'https:/a.test', 'https:\\\\a.test', 'hxxps://a.test/', 'https\u200b://a.test/']


def test_an_explicitly_empty_port_is_invalid_in_both_detection_paths():
    """urlsplit().port is None both for 'a.test' and for 'a.test:'; only the first has no explicit port."""
    for url in ('https://a.test:/x', 'https://u:p@a.test:/x', 'https://[::1]:/x'):
        assert detect(failures=[(url, 10, 'm')]) == []                        # certificate-failure detection
        assert detect([resp(url, 'TLSv1')]) == [] and detect([resp(url, 'TLSv1.3')]) == []      # protocol-version detection


@pytest.mark.parametrize('url,key', [
    ('https://a.test/x', 'a.test'),                      # no explicit port: valid, the default 443
    ('https://a.test:443/x', 'a.test'),                  # explicit default port: the same endpoint
    ('https://a.test:8443/x', 'a.test:8443'),            # explicit valid port
    ('https://a.test:1/', 'a.test:1'), ('https://a.test:65535/', 'a.test:65535'),
    ('https://[::1]/x', '[::1]'), ('https://[::1]:8443/x', '[::1]:8443'), ('https://u:p@a.test:8443/x', 'a.test:8443')])
def test_absent_and_explicit_valid_ports_are_still_accepted(url, key):
    assert detect(failures=[(url, 10, '')])[0].extra['host'] == key
    assert detect([resp(url, 'TLSv1')])[0].extra['host'] == key


@pytest.mark.parametrize('url', ['https://a.test:0/', 'https://a.test:65536/', 'https://a.test:-1/', 'https://a.test:abc/', 'https://a.test:+80/',
                                 'https://a.test: 80/', 'https://a.test:80:80/', 'https://[::1]:0/', 'https://[::1]:99999/', 'https://[::1]x/'])
def test_malformed_or_out_of_range_ports_are_invalid(url):
    assert detect(failures=[(url, 10, '')]) == [] and detect([resp(url, 'TLSv1')]) == []


def test_hostnames_with_underscores_are_rejected_like_phase_2_scope_validation():
    """Regression: 'lab_host.test' used to be accepted (a deliberate superset). The policy is now strict RFC 1123."""
    import scanner.detectors.tls_security as module
    from scanner.scope_validator import _HOST_RE
    assert not module._valid_hostname('lab_host.test') and not _HOST_RE.match('lab_host.test')
    for url in ('https://lab_host.test/', 'https://lab_host.test:8443/', 'https://_dmarc.a.test/', 'https://a._b.test/', 'https://a_.test/',
                'https://_a.test/', 'https://u:p@lab_host.test/', 'HTTPS://LAB_HOST.TEST/', 'https://a.test_/', 'https://lab_host-1.example.test:65535/'):
        assert detect(failures=[(url, 10, 'm')]) == [], url
        assert detect([resp(url, 'TLSv1')]) == [] and detect([resp(url, 'TLSv1.3')]) == [], url
    assert detect(failures=[('https://lab-host.test/', 10, '')])[0].extra['host'] == 'lab-host.test'       # a hyphen is fine


def test_the_host_name_policy_is_strict_rfc_1123_and_documented():
    import scanner.detectors.tls_security as module
    doc = module._valid_hostname.__doc__
    assert 'strict RFC 1123' in doc and 'NO underscores' in doc and "scope_validator._HOST_RE" in doc and 'MIRRORS Phase 2' in doc
    assert 'superset' not in doc and "'_' ALSO accepted" not in doc
    assert 'underscore' in module.__doc__ and 'RFC 1123' in module.__doc__


def phase_2_accepts(host):
    """Phase 2's EFFECTIVE host rule: scope_validator._normalize_host (its _HOST_RE plus the ambiguous-numeric-host check)."""
    from scanner.scope_validator import ScopeError, _normalize_host
    try:
        _normalize_host(host)
        return True
    except ScopeError:
        return False


@pytest.mark.parametrize('host', ['a.0x7f', 'a.0xff', 'a.0x', 'a.0xzz', 'a.0xtest', 'a.0x0', '0x7f.0.0.1', 'test.0x1a', 'x.y.0xdeadbeef', '0x7f', '0xff'])
def test_a_last_label_starting_with_0x_is_rejected_like_phase_2(host):
    import scanner.detectors.tls_security as module
    assert not phase_2_accepts(host) and not module._valid_hostname(host)
    for url in (f'https://{host}/', f'https://{host}:8443/', f'https://u:p@{host}/', f'HTTPS://{host.upper()}/', f'https://{host}./'):
        assert detect(failures=[(url, 10, 'm')]) == [], url
        assert detect([resp(url, 'TLSv1')]) == [] and detect([resp(url, 'TLSv1.3')]) == [], url


@pytest.mark.parametrize('host', ['x.0x1.test', '0xa.test', 'a0x.test', 'a.b0x', 'a.x0x7f', 'a.t0x', '0x.test'])
def test_0x_is_rejected_only_as_the_last_label_like_phase_2(host):
    """Phase 2 checks only the final label, so '0x' elsewhere (or not at the start of the final label) is fine."""
    import scanner.detectors.tls_security as module
    assert phase_2_accepts(host) and module._valid_hostname(host)
    assert detect(failures=[(f'https://{host}/', 10, '')])[0].extra['host'] == host


@pytest.mark.parametrize('host', ['1.2.3.4.5', '256.256.256.256.256', 'a.1', 'a.09', '127.1', '2130706433', 'a.b.123'])
def test_an_all_digit_last_label_is_rejected_like_phase_2(host):
    import scanner.detectors.tls_security as module
    assert not phase_2_accepts(host) and not module._valid_hostname(host)
    assert detect(failures=[(f'https://{host}/', 10, '')]) == []


def test_tls_host_validation_equals_phase_2_effective_normalisation():
    """For ASCII, lower-case, non-IP names TLS validation and scope_validator._normalize_host give the same answer."""
    import ipaddress
    import random
    import scanner.detectors.tls_security as module
    rnd = random.Random(1123)
    alphabet = 'ab0x-_.19'
    names = {''.join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 12))) for _ in range(40000)}
    names |= {'a.test', 'a-b.test', 'a.b.c.test', '-a.test', 'a-.test', 'a..test', '.a', 'a_b.test', '_a', 'a' * 63 + '.test', 'a' * 64 + '.test',
              'a.' * 120 + 'test', 'a.0x7f', 'a.0xff', '1.2.3.4.5', 'a.1', '1a.test', 'test.1a', 'x.0x1.test', '0xa.test'}

    def literal(h):
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            return False
    names = {h for h in names if not h.endswith('.') and not literal(h)}                   # literals are handled before _valid_hostname
    mismatches = sorted(h for h in names if module._valid_hostname(h) != phase_2_accepts(h))
    assert mismatches == [], mismatches[:10]
    accepted = [h for h in names if module._valid_hostname(h)]
    assert len(accepted) > 500 and any(h.split('.')[-1].startswith('0x') for h in names) and all('_' not in h for h in accepted)


def test_the_documented_numeric_host_policy_mirrors_phase_2():
    import scanner.detectors.tls_security as module
    doc = module._valid_hostname.__doc__
    assert "all digits or starts with '0x'" in doc and 'MIRRORS Phase 2' in doc and '_normalize_host' in doc and 'ambiguous numeric host' in doc
    assert 'STRICTER direction' not in doc and 'never accepts a name that Phase 2' not in doc



@pytest.mark.parametrize('url', INVALID_URLS)
def test_invalid_or_non_https_failure_urls_produce_no_finding(url):
    assert detect(failures=[(url, 10, 'm')]) == []
    assert detect(failures=[(url, 62, 'm'), (url, None, None)]) == []


@pytest.mark.parametrize('url', INVALID_URLS)
def test_invalid_or_non_https_response_urls_produce_no_protocol_finding(url):
    assert detect([resp(url, 'TLSv1')]) == [] and detect([resp(url, 'TLSv1.3')]) == []


@pytest.mark.parametrize('url', [None, 5, 5.5, b'https://a.test/', ['https://a.test/'], ('https://a.test/',), {'u': 1}, object()])
def test_non_string_urls_produce_no_finding(url):
    assert detect(failures=[(url, 10, 'm')]) == []


def test_an_invalid_record_does_not_hide_valid_ones_around_it():
    found = detect(failures=[('http://a.test/', 10, ''), ('https://a.test:99999/', 10, ''), ('https://ok.test/', 10, ''), ('//x.test/', 10, '')])
    assert [f.extra['host'] for f in found] == ['ok.test']


@pytest.mark.parametrize('url,code,rule', [
    ('https://a.test/', 10, 'TLS-CERT-EXPIRED'), ('HTTPS://a.test/', 9, 'TLS-CERT-NOT-YET-VALID'), ('https://a.test:8443/x?y=1', 62, 'TLS-CERT-HOSTNAME-MISMATCH'),
    ('https://192.0.2.1/', 64, 'TLS-CERT-HOSTNAME-MISMATCH'), ('https://[::1]:8443/', 18, 'TLS-CERT-SELF-SIGNED'), ('https://a.test/', 20, 'TLS-CERT-UNTRUSTED'),
    ('https://a.test/', 7, 'TLS-CERT-INVALID'), ('https://u:p@a.test/', 10, 'TLS-CERT-EXPIRED')])
def test_valid_https_certificate_failures_are_still_detected(url, code, rule):
    found = detect(failures=[(url, code, 'm')])
    assert rules(found) == {rule} and found[0].confidence in ('Confirmed', 'Potential')


def test_the_urls_stored_in_findings_are_https_only_credential_free_and_keep_their_path_and_query():
    f = detect(failures=[('HTTPS://u:p@A.test:443/Path/x?q=1#frag', 10, '')])[0]
    assert f.affected_urls == ['https://a.test/Path/x?q=1']                                   # the query stays: it is page identity


def test_url_scope_identity_is_unaffected_by_credentials_in_the_same_endpoint():
    a = detect(failures=[('https://u:p@a.test/x?q=1', 10, '')])[0]
    b = detect(failures=[('https://a.test:443/x?q=1', 10, '')])[0]
    assert a.affected_urls == b.affected_urls and a.fingerprint() == b.fingerprint()


# ---------------------------------------------------------------- passive by construction
def test_the_detector_never_touches_the_client():
    detect([resp('https://a.test/', 'TLSv1.3')], [('https://a.test/', 10, '')], client=ForbiddenClient())


def test_the_detector_source_has_no_network_or_logging_access():
    code = re.sub(r'""".*?"""', '', (ROOT / 'scanner' / 'detectors' / 'tls_security.py').read_text(encoding='utf-8'), flags=re.S)
    for forbidden in (r'\.client\b', r'\bssl\b', r'\bsocket\b', r'urllib\.request', r'http\.client', r'(import|from) requests\b',
                      r'\bprint\(', r'\blogging\b', r'getpeercert', r'\.body\b'):
        assert not re.search(forbidden, code), f'tls_security.py must not use {forbidden}'
    import ast
    handlers = [n for n in ast.walk(ast.parse(code)) if isinstance(n, ast.ExceptHandler)]
    # The only handlers are the two narrow ones in _endpoint: urlsplit()/.port and ipaddress.ip_address(), both ValueError.
    assert [ast.unparse(h.type) for h in handlers] == ['ValueError', 'ValueError']


def test_registry_and_catalog():
    assert 'ssl_tls' in CATEGORIES
    assert [d.name for d in get_detectors({'ssl_tls'})] == ['tls-security']
    assert [d.name for d in get_detectors({'cookie_security'})] == ['cookie-security']
    for rule in ('TLS-CERT-EXPIRED', 'TLS-CERT-NOT-YET-VALID', 'TLS-CERT-HOSTNAME-MISMATCH', 'TLS-CERT-SELF-SIGNED', 'TLS-CERT-UNTRUSTED',
                 'TLS-CERT-INVALID', 'TLS-PROTOCOL-OBSOLETE', 'TLS-LEGACY-UNTESTED'):
        assert get_rule(rule).category == 'ssl_tls'


def test_the_detector_error_handling_is_absent_so_bugs_surface(monkeypatch):
    import scanner.detectors.tls_security as module

    def broken(found, failures):
        raise RuntimeError('bug')
    monkeypatch.setattr(module.TlsSecurityDetector, '_certificate_failures', staticmethod(broken))
    with pytest.raises(RuntimeError):
        detect([resp()])


# ---------------------------------------------------------------- plumbing: what the crawler keeps
def test_fetch_error_carries_the_verifier_number_and_failing_url_by_default_none():
    e = FetchError('tls_cert_invalid', 'TLS certificate verification failed.', verify_message='m', verify_code=10)
    assert (e.verify_code, e.url, e.verify_message, str(e)) == (10, None, 'm', 'TLS certificate verification failed.')
    assert FetchError('timeout', 'x').verify_code is None


def test_crawl_result_default_and_repr_are_unchanged_by_the_new_field():
    c = CrawlResult()
    assert c.tls_failures == [] and 'tls_failures' not in repr(c)
    c.tls_failures.append(('https://x.test/p?sig=QUERYSEC', 10, 'm'))
    assert 'QUERYSEC' not in repr(c) and 'x.test' not in repr(c)


def test_the_failing_redirect_hop_is_recorded_not_the_url_that_was_requested(make_server, make_client, monkeypatch):
    srv = make_server({})
    client = make_client(srv)
    hop2 = srv.base + '/second'
    calls = []

    def fake(self, method, url, headers, verify_tls):
        calls.append(url)
        if len(calls) == 1:
            return HttpResponse(url=url, method='GET', status=302, reason='', headers=[('Location', '/second')], body=b'', truncated=False,
                                ip='127.0.0.1', scheme='http')
        raise FetchError('tls_cert_invalid', 'TLS certificate verification failed.', verify_message='certificate has expired', verify_code=10)
    monkeypatch.setattr(ScanHTTPClient, '_single_request', fake)
    with pytest.raises(FetchError) as exc:
        client.request('GET', srv.base + '/first')
    assert exc.value.url == hop2 and exc.value.verify_code == 10 and calls[-1] == hop2


# ---------------------------------------------------------------- evidence aggregation (one finding per rule and host)
def _untrusted(found):
    return only(found, 'TLS-CERT-UNTRUSTED')


def test_distinct_openssl_errors_on_one_host_are_each_attributed_to_their_own_url():
    found = detect(failures=[('https://a.test/a', 19, ''), ('https://a.test/b', 20, '')])
    assert len(found) == 1
    f = found[0]
    assert f.extra['rule'] == 'TLS-CERT-UNTRUSTED' and f.confidence == 'Potential' and f.severity == 'Medium'
    assert sorted(f.affected_urls) == ['https://a.test/a', 'https://a.test/b']
    assert 'self-signed certificate in the certificate chain' in f.evidence
    assert '(OpenSSL verification error 19): https://a.test/a.' in f.evidence
    assert '(OpenSSL verification error 20): https://a.test/b.' in f.evidence
    assert 'error 20): https://a.test/a' not in f.evidence and 'error 19): https://a.test/b' not in f.evidence
    assert "scanner host's trust store" in f.evidence and 'only the first problem' in f.evidence


def test_distinct_reasons_are_ordered_deterministically_whatever_the_crawl_order():
    forward = detect(failures=[('https://a.test/a', 19, ''), ('https://a.test/b', 20, ''), ('https://a.test/c', 21, '')])[0]
    backward = detect(failures=[('https://a.test/c', 21, ''), ('https://a.test/b', 20, ''), ('https://a.test/a', 19, '')])[0]
    assert forward.evidence == backward.evidence
    assert forward.evidence.index('error 19') < forward.evidence.index('error 20') < forward.evidence.index('error 21')


def test_repeated_identical_errors_on_one_url_give_one_reason_and_one_url():
    f = detect(failures=[('https://a.test/a', 19, '')] * 3)[0]
    assert f.affected_urls == ['https://a.test/a']
    assert f.evidence.count('error 19') == 1 and 'different reasons' not in f.evidence and 'requests to this host' not in f.evidence


def test_several_urls_sharing_one_error_give_a_single_reason_with_a_count():
    f = detect(failures=[('https://a.test/a', 20, ''), ('https://a.test/b', 20, ''), ('https://a.test/a', 20, '')])[0]
    assert sorted(f.affected_urls) == ['https://a.test/a', 'https://a.test/b']
    assert f.evidence.count('error 20') == 1 and 'different reasons' not in f.evidence
    assert '2 requests to this host:port showed this.' in f.evidence


def test_a_shared_error_and_a_different_error_attribute_every_url_correctly():
    f = detect(failures=[('https://a.test/a', 19, ''), ('https://a.test/b', 20, ''), ('https://a.test/c', 19, '')])[0]
    assert sorted(f.affected_urls) == ['https://a.test/a', 'https://a.test/b', 'https://a.test/c']
    assert 'error 19): https://a.test/a, https://a.test/c.' in f.evidence and 'error 20): https://a.test/b.' in f.evidence


def test_distinct_invalid_reasons_on_one_host_are_all_kept():
    f = detect(failures=[('https://a.test/a', 7777, 'first odd thing'), ('https://a.test/b', 8888, 'second odd thing')])[0]
    assert f.extra['rule'] == 'TLS-CERT-INVALID' and f.confidence == 'Confirmed'
    assert 'verification error 7777: first odd thing): https://a.test/a.' in f.evidence
    assert 'verification error 8888: second odd thing): https://a.test/b.' in f.evidence


def test_different_hosts_still_get_separate_findings_per_rule():
    found = detect(failures=[('https://a.test/', 19, ''), ('https://b.test/', 20, '')])
    assert len(found) == 2 and {f.extra['host'] for f in found} == {'a.test', 'b.test'}


def test_aggregated_evidence_is_sanitised_and_never_leaks_credentials():
    found = detect(failures=[('https://user:secret@a.test/a?token=abc', 19, ''), ('https://u2:pw2@a.test/b', 20, '')])
    assert len(found) == 1
    shown = repr(found[0]) + json.dumps(found[0].to_dict(), default=str) + found[0].evidence
    for leaked in ('secret', 'pw2', 'user:', 'u2:', 'token=abc'):
        assert leaked not in shown


def test_aggregated_evidence_is_bounded_when_there_are_many_reasons_and_urls():
    failures = [(f'https://a.test/{i}', 7000 + i, 'x' * 500) for i in range(40)]
    f = detect(failures=failures)[0]
    assert len(f.affected_urls) == 40 and len(f.evidence) <= 2000
    assert 'more reason(s) not listed' in f.evidence
    many = detect(failures=[(f'https://a.test/{i}', 19, '') for i in range(10)])[0]
    assert len(many.affected_urls) == 10 and '10 requests to this host:port showed this.' in many.evidence


def test_many_urls_for_one_of_several_reasons_are_counted_not_all_listed():
    failures = [(f'https://a.test/{i}', 19, '') for i in range(6)] + [('https://a.test/z', 20, '')]
    f = detect(failures=failures)[0]
    assert len(f.affected_urls) == 7 and 'and 3 more' in f.evidence and 'error 20): https://a.test/z.' in f.evidence


def test_mixed_obsolete_protocol_versions_on_one_host_are_each_attributed():
    found = detect([resp('https://a.test/a', 'TLSv1'), resp('https://a.test/b', 'TLSv1.1'), resp('https://a.test/c', 'TLSv1')])
    f = only(found, 'TLS-PROTOCOL-OBSOLETE')
    assert sorted(f.affected_urls) == ['https://a.test/a', 'https://a.test/b', 'https://a.test/c']
    assert f.confidence == 'Confirmed' and f.severity == 'Medium'
    assert 'TLSv1 (' in f.evidence and 'TLSv1.1 (' in f.evidence
    assert 'https://a.test/a, https://a.test/c.' in f.evidence and 'https://a.test/b.' in f.evidence


def test_failures_are_bounded_without_copying_the_whole_input():
    def endless():
        i = 0
        while True:
            i += 1
            yield (f'https://h{i}.test/', 10, '')
    found = detect(crawl_result=SimpleNamespace(tls_failures=endless()))      # a bare iterator: only MAX_FAILURES items are consumed
    assert len(found) == MAX_FAILURES


def test_urls_listed_under_one_reason_are_sorted_whatever_the_crawl_order():
    one = detect(failures=[('https://a.test/c', 19, ''), ('https://a.test/a', 19, ''), ('https://a.test/b', 20, '')])[0]
    two = detect(failures=[('https://a.test/b', 20, ''), ('https://a.test/a', 19, ''), ('https://a.test/c', 19, '')])[0]
    assert one.evidence == two.evidence and 'https://a.test/a, https://a.test/c.' in one.evidence


def test_affected_urls_are_identical_across_reversed_input_orders_without_sorting():
    failures = [('https://a.test/c', 19, ''), ('https://a.test/a', 20, ''), ('https://a.test/b', 19, '')]
    one = detect(failures=failures)[0]
    two = detect(failures=failures[::-1])[0]
    assert one.affected_urls == two.affected_urls                      # compared directly: order is part of the contract
    assert one.fingerprint() == two.fingerprint() and one.evidence == two.evidence
    pages = [resp('https://a.test/z', 'TLSv1'), resp('https://a.test/m', 'TLSv1.1'), resp('https://a.test/a', 'TLSv1')]
    p1, p2 = only(detect(pages), 'TLS-PROTOCOL-OBSOLETE'), only(detect(pages[::-1]), 'TLS-PROTOCOL-OBSOLETE')
    assert p1.affected_urls == p2.affected_urls and p1.fingerprint() == p2.fingerprint()
