import pytest

from scanner.models import Finding
from scanner.result_processor import dedupe, redact


def make(rule='HDR-X', url='http://a.test/', severity='Low', confidence='Confirmed', evidence='ev', scope='host', **kw):
    return Finding(rule_id=rule, title='t', category='security_headers', severity=severity,
                   confidence=confidence, description='d', affected_urls=[url] if isinstance(url, str) else url,
                   evidence=evidence, impact='i', remediation='r', reference='ref',
                   detection_method='m', dedupe_scope=scope, **kw)


def test_finding_validation():
    with pytest.raises(ValueError):
        make(severity='Severe')
    with pytest.raises(ValueError):
        make(confidence='Certain')
    with pytest.raises(ValueError):
        make(url=[])
    with pytest.raises(ValueError):
        make(scope='global')
    with pytest.raises(ValueError, match='evidence'):
        make(confidence='Confirmed', evidence='  ')
    make(confidence='Potential', evidence='')              # allowed: heuristics may lack hard evidence
    make(severity='Informational', confidence='Informational')


def test_evidence_is_capped_and_urls_deduplicated():
    f = make(evidence='x' * 5000, url=['http://a.test/', 'http://a.test/'])
    assert len(f.evidence) == 2000 and f.affected_urls == ['http://a.test/']


def test_fingerprint_host_scope():
    a, b = make(url='http://a.test/one'), make(url='http://A.test/two?x=1')
    assert a.fingerprint() == b.fingerprint()                                  # same site-wide issue
    assert a.fingerprint() != make(rule='HDR-Y').fingerprint()                 # different rule
    assert a.fingerprint() != make(url='http://b.test/').fingerprint()         # different host
    assert a.fingerprint() != make(url='http://a.test:8080/').fingerprint()    # different port = different service


def test_fingerprint_url_scope():
    a = make(scope='url', url='http://a.test/x#frag')
    assert a.fingerprint() == make(scope='url', url='http://A.test/x').fingerprint()
    assert a.fingerprint() != make(scope='url', url='http://a.test/y').fingerprint()
    assert a.fingerprint() != make(scope='url', url='http://a.test/x?q=1').fingerprint()
    assert len(a.fingerprint()) == 32


def test_dedupe_merges_urls_keeps_order_and_highest_severity():
    f1 = make(url='http://a.test/1', severity='Low')
    f2 = make(url='http://a.test/2', severity='High')
    other = make(rule='HDR-Y', url='http://a.test/1')
    f3 = make(url='http://a.test/1')
    out = dedupe([f1, other, f2, f3])
    assert [f.rule_id for f in out] == ['HDR-X', 'HDR-Y']
    assert out[0].affected_urls == ['http://a.test/1', 'http://a.test/2'] and out[0].severity == 'High'


def test_dedupe_url_scope_keeps_separate_findings():
    out = dedupe([make(scope='url', url='http://a.test/1'), make(scope='url', url='http://a.test/2')])
    assert len(out) == 2


@pytest.mark.parametrize('text,gone', [
    ('Authorization: Bearer abcdefghijklmnop1234', 'abcdefghijklmnop1234'),
    ('password=hunter2hunter2', 'hunter2hunter2'),
    ('{"api_key": "sk_live_abcdef123456"}', 'sk_live_abcdef123456'),
    ('key AKIAIOSFODNN7EXAMPLE here', 'AKIAIOSFODNN7EXAMPLE'),
    ('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123', 'eyJhbGciOiJIUzI1NiJ9'),
    ('contact admin@example.com for help', 'admin@example.com'),
    ('card 4111 1111 1111 1111 on file', '4111 1111 1111 1111'),
    ('-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----', 'MIIEow'),
])
def test_redaction(text, gone):
    out = redact(text)
    assert gone not in out and 'REDACTED' in out.upper()


def test_redaction_leaves_ordinary_evidence_alone():
    text = 'Server: nginx/1.18.0\nStrict-Transport-Security header is absent on https://a.test/'
    assert redact(text) == text and redact(None) == ''
