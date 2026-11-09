"""
Raw URL exposure: a crawled URL can carry secrets (session ids, signatures, userinfo, fragments). Raw URLs
are an INTERNAL identity (de-duplication, fingerprints); every outward-facing path must show the sanitized
form. These tests cover serialization, display properties, repr/str/format, logging, error messages and the
source tree itself (a guard that codifies the audit, so new code cannot quietly read or log raw URLs).
"""
import hashlib
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

from scanner.engine import ScanEngine
from scanner.http_client import ScanHTTPClient
from scanner.result_processor import dedupe
from scanner.rules import build_finding
from scanner.scope_validator import ScopeError

ROOT = Path(__file__).resolve().parents[1]
RAW = 'https://u:hunter2@a.test:8443/p;jsessionid=PATHSECRET/q?sig=ZZSECRET123&session=SESSSECRET&bare#access_token=FRAGSECRET'
LEAKS = ('ZZSECRET123', 'SESSSECRET', 'FRAGSECRET', 'PATHSECRET', 'hunter2', 'access_token', 'sig=Z', 'u:hunter')


def finding(rule='HDR-CSP-MISSING', urls=(RAW,), evidence='GET https://a.test/ returned HTTP 200 without a header.'):
    return build_finding(rule, list(urls), evidence)


def assert_clean(text, where):
    for leak in LEAKS:
        assert leak not in text, f'{leak!r} leaked through {where}: {text[:200]!r}'


# ---------------------------------------------------------------- the public single-URL property
def test_affected_url_property_is_the_sanitized_url():
    f = finding()
    assert f.affected_url == f.display_url == f.display_urls[0] == f.to_dict()['affected_url']
    assert f.affected_url == 'https://a.test:8443/p;jsessionid=[redacted]/q?sig=[redacted]&session=[redacted]&[redacted]'
    assert_clean(f.affected_url, 'Finding.affected_url')
    assert 'a.test:8443/p' in f.affected_url and '/q?sig=' in f.affected_url          # still identifies the page


def test_raw_url_is_only_available_through_the_explicitly_internal_list():
    f = finding()
    assert f.affected_urls == [RAW]                      # internal identity, unmasked by design
    assert len(f.display_urls) == len(f.affected_urls)


# ---------------------------------------------------------------- identity / dedupe / fingerprints are unchanged
def _expected_fingerprint(rule_id, scope, url):
    parts = urlsplit(url)
    key = parts.netloc.lower() if scope == 'host' else urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or '/', parts.query, ''))
    return hashlib.sha256(f'{rule_id}|{key}'.encode()).hexdigest()[:32]


def test_fingerprints_still_use_the_raw_url_exactly_as_before():
    host_scoped = finding('HDR-CSP-MISSING')
    url_scoped = finding('INFO-VERBOSE-ERROR')
    assert host_scoped.dedupe_scope == 'host' and url_scoped.dedupe_scope == 'url'
    assert host_scoped.fingerprint() == _expected_fingerprint('HDR-CSP-MISSING', 'host', RAW)
    assert url_scoped.fingerprint() == _expected_fingerprint('INFO-VERBOSE-ERROR', 'url', RAW)   # includes the raw query


def test_pages_differing_only_by_query_value_remain_distinct_after_the_sanitizing_change():
    a, b = 'https://a.test/p?id=1&sig=AAA', 'https://a.test/p?id=2&sig=BBB'
    fa, fb = finding('INFO-VERBOSE-ERROR', [a]), finding('INFO-VERBOSE-ERROR', [b])
    assert fa.fingerprint() != fb.fingerprint()                         # url scope: two pages, two identities
    assert fa.affected_url == fb.affected_url                           # ...although their display text is identical
    assert len(dedupe([fa, fb, finding('INFO-VERBOSE-ERROR', [a])])) == 2
    (merged,) = dedupe([finding('HDR-CSP-MISSING', [a]), finding('HDR-CSP-MISSING', [b])])
    assert merged.affected_urls == [a, b] and len(merged.display_urls) == 2


# ---------------------------------------------------------------- serialization
def test_to_dict_exposes_no_raw_url_in_any_field():
    f = finding(evidence=f'GET {RAW} returned 200; see {RAW}')
    d = f.to_dict()
    assert set(d) == {'rule_id', 'title', 'category', 'severity', 'confidence', 'description', 'affected_urls',
                      'affected_url', 'evidence', 'impact', 'remediation', 'reference', 'detection_method',
                      'fingerprint'}
    assert_clean(json.dumps(d), 'to_dict()/json')
    assert d['affected_url'] == d['affected_urls'][0]


@pytest.mark.parametrize('url', [RAW, 'http://[::1]:8080/x?k=SECRETVAL#frag', 'https://a.test/?a=1&a=2&token=T0KEN12345',
                                 'https://a.test/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij/x'])
def test_to_dict_is_safe_for_awkward_urls(url):
    blob = json.dumps(finding(urls=[url], evidence=f'GET {url}').to_dict())
    for secret in ('SECRETVAL', 'T0KEN12345', 'eyJhbGciOi', 'FRAGSECRET', 'hunter2'):
        assert secret not in blob


# ---------------------------------------------------------------- repr / str / format / print / logging
def test_repr_str_and_format_never_show_raw_data():
    f = finding(evidence=f'GET {RAW}')
    f.extra['note'] = RAW                                 # even a free-text field a detector might fill later
    forms = {'repr': repr(f), 'str': str(f), 'format': format(f), 'f-string': f'{f}', '%s': '%s' % f, '%r': '%r' % f,
             'list repr': repr([f]), 'dict repr': repr({'finding': f}), 'tuple': str((f, f))}
    for where, text in forms.items():
        assert_clean(text, where)
    assert "rule_id='HDR-CSP-MISSING'" in repr(f) and "severity='Medium'" in repr(f) and 'a.test:8443' in repr(f)


def test_printing_a_finding_does_not_expose_raw_urls(capsys):
    f = finding()
    print(f, [f], f.to_dict())
    assert_clean(capsys.readouterr().out, 'print()')


def test_logging_findings_by_any_common_style_does_not_expose_raw_urls(caplog):
    f = finding()
    logger = logging.getLogger('anything')
    with caplog.at_level(logging.DEBUG):
        logger.info('finding: %s', f)
        logger.info('finding: %r', f)
        logger.info('findings: %s', [f])
        logger.warning(f'fstring {f}')
        logger.debug('dict: %s', f.to_dict())
        try:
            raise ValueError(f'bad finding {f}')
        except ValueError:
            logger.exception('failed for %s', f)             # traceback text includes the exception message
    assert_clean(caplog.text, 'logging')
    assert len(caplog.records) == 6


# ---------------------------------------------------------------- end to end through the engine
@pytest.fixture
def engine(lab_config, resolver, clock):
    def factory(target, config, resolver):
        return ScanHTTPClient(target, config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    return ScanEngine(config=lab_config, resolver=resolver, client_factory=factory)


def test_engine_scan_exposes_no_raw_url_in_outcome_logs_or_serialization(make_server, engine, caplog, capsys):
    H = {'Content-Type': 'text/html'}
    page = b'<a href="/p?sig=PAGESECRET&session=SESSIONSECRET#frag">p</a>'
    srv = make_server({'/': (200, H, page), '/p': (200, H, b'x')})
    with caplog.at_level(logging.DEBUG):
        out = engine.run(srv.base + '/', True, {'security_headers'})
    assert out.findings and any('/p?' in u for f in out.findings for u in f.affected_urls)   # raw kept internally
    secrets = ('PAGESECRET', 'SESSIONSECRET')
    blobs = {'repr(outcome)': repr(out), 'str(findings)': str(out.findings), 'caplog': caplog.text,
             'stdout/stderr': ''.join(capsys.readouterr()), 'to_dict': json.dumps([f.to_dict() for f in out.findings]),
             'display': json.dumps([f.display_urls for f in out.findings]),
             'affected_url': ' '.join(f.affected_url for f in out.findings),
             'errors/notes': ' '.join(out.errors + out.notes)}
    for where, text in blobs.items():
        for secret in secrets:
            assert secret not in text, f'{secret} leaked through {where}'
    assert not [r for r in caplog.records if r.name.startswith('scanner')]     # the scanner emits no log records at all


def test_scope_errors_do_not_echo_url_queries_or_credentials(engine):
    for url in ('http://notallowed.test/p?token=SECRETTOKEN#frag', 'ftp://a.test/?token=SECRETTOKEN',
                'http://a.test:99999/?token=SECRETTOKEN', 'http://user:hunter2@a.test/?token=SECRETTOKEN'):
        with pytest.raises(ScopeError) as err:
            engine.run(url, True, {'security_headers'})
        for text in (str(err.value), err.value.message, repr(err.value)):
            assert 'SECRETTOKEN' not in text and 'hunter2' not in text


# ---------------------------------------------------------------- source-tree guards (the audit, codified)
def _python_files(*dirs):
    for d in dirs:
        yield from (ROOT / d).rglob('*.py')


def test_only_identity_code_reads_the_raw_url_list():
    """New code must use display_urls/to_dict(), or be added here after a conscious security review."""
    allowed = {'scanner/models.py', 'scanner/result_processor.py', 'scanner/rules/__init__.py'}
    offenders = []
    for path in list(_python_files('scanner')) + [ROOT / 'app.py']:
        rel = path.relative_to(ROOT).as_posix()
        if rel not in allowed and re.search(r'\baffected_urls\b', path.read_text(encoding='utf-8')):
            offenders.append(rel)
    assert offenders == [], f'{offenders} read Finding.affected_urls (raw URLs); use display_urls or to_dict()'


def test_raw_single_url_property_is_not_used_by_any_user_facing_code():
    for pattern in ('templates', 'static'):
        for path in (ROOT / pattern).rglob('*'):
            if path.is_file() and path.suffix in {'.html', '.js'} and 'vendor' not in path.as_posix():
                text = path.read_text(encoding='utf-8', errors='ignore')
                assert 'affected_url' not in text, f'{path} references finding URLs; use the serialized API fields'


def test_scanner_package_has_no_print_or_logging_sinks():
    """Today the scanner never prints or logs. If logging is added, it must be reviewed for raw URLs first."""
    sink = re.compile(r'\bprint\(|import logging|from logging|getLogger|\blogger\.|app\.logger|traceback\.print')
    offenders = [p.relative_to(ROOT).as_posix() for p in _python_files('scanner') if sink.search(p.read_text(encoding='utf-8'))]
    assert offenders == [], f'{offenders} print/log; make sure raw URLs and secrets are never emitted'


def test_flask_app_does_not_serialize_scanner_findings_yet():
    """app.py only uses scanner.config for the network-binding guard; finding serialization arrives in a later phase."""
    text = (ROOT / 'app.py').read_text(encoding='utf-8')
    assert re.findall(r'^\s*(?:from|import)\s+scanner[\w.]*.*$', text, re.M) == [
        '    from scanner.config import ConfigError, check_network_binding, ENV_API_TOKEN, ENV_HOST']
