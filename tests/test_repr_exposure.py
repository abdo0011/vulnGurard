"""
Sensitive data in object representations.

Logging, printing or debugging a Phase 2 object must not expose URL query values or credentials, response
headers (Set-Cookie, Authorization, API keys), response bodies or the API token. These tests cover each
object, nested objects, a real scan, and a guard over every dataclass in the package. They also prove the
hardening is representation-only: the underlying data, equality and behaviour are unchanged.
"""
import dataclasses
import importlib
import inspect
import json
import logging
import pkgutil
import re
from pathlib import Path

import pytest

import scanner
from scanner.config import ScannerConfig, load_config
from scanner.crawler import CrawlResult, Page
from scanner.detectors import BaseDetector, register, unregister
from scanner.engine import ScanContext, ScanEngine, ScanOutcome
from scanner.http_client import HttpResponse, ScanHTTPClient
from scanner.rules import build_finding
from scanner.scope_validator import ValidatedTarget, validate_scan_request

ROOT = Path(__file__).resolve().parents[1]
RAW_URL = 'https://user:pw123@a.test:8443/p;sess=PATHSEC/q?sig=QUERYSEC&token=TOKSEC#FRAGSEC'
HEADERS = [('Content-Type', 'text/html'), ('Set-Cookie', 'session=COOKIESEC; HttpOnly'),
           ('Set-Cookie', 'csrf=COOKIE2SEC'), ('Authorization', 'Bearer HDRBEARERSEC'),
           ('X-Api-Key', 'APIKEYSEC'), ('X-Internal', 'INTERNALHDRSEC')]
BODY = b'<html>password=BODYPWSEC api_key=BODYKEYSEC <a href="/next?x=BODYLINKSEC">n</a>' + b'A' * 5000 + b'</html>'
SECRETS = ('user:pw123', 'pw123', 'PATHSEC', 'QUERYSEC', 'TOKSEC', 'FRAGSEC', 'COOKIESEC', 'COOKIE2SEC', 'HDRBEARERSEC',
           'APIKEYSEC', 'INTERNALHDRSEC', 'BODYPWSEC', 'BODYKEYSEC', 'BODYLINKSEC', 'REDIRSECRET', 'TARGETSEC', 'TOKENVALUE')


def assert_clean(text, where):
    for secret in SECRETS:
        assert secret not in text, f'{secret!r} leaked through {where}: {text[:240]!r}'


def response(**kw):
    base = dict(url=RAW_URL, method='GET', status=200, reason='OK', headers=list(HEADERS), body=BODY, truncated=False,
                ip='93.184.216.34', scheme='https', tls_version='TLSv1.3', elapsed=0.12,
                redirect_chain=['https://a.test/start?token=REDIRSECRET', RAW_URL],
                redirect_blocked=('https://evil.test/x?sig=REDIRSECRET', 'out_of_scope'))
    base.update(kw)
    return HttpResponse(**base)


def every_form(obj):
    return {'repr': repr(obj), 'str': str(obj), 'format': format(obj), 'f-string': f'{obj}', '%s': '%s' % obj,
            '%r': '%r' % obj, 'list': repr([obj]), 'dict': repr({'k': obj}), 'tuple': str((obj, obj)),
            'nested list': repr([[obj], {'x': [obj]}])}


# ---------------------------------------------------------------- HttpResponse
def test_http_response_repr_hides_url_secrets_headers_and_body():
    r = response()
    for where, text in every_form(r).items():
        assert_clean(text, f'HttpResponse {where}')
    text = repr(r)
    assert "status=200" in text and "method='GET'" in text and 'a.test:8443/p' in text      # still useful for debugging
    assert '<6 headers>' in text and f'body=<{len(BODY)} bytes>' in text and 'redirects=2' in text
    assert 'redirect_blocked=' in text and 'out_of_scope' in text
    assert len(text) < 400                                                                    # the 5 KB body is not echoed


def test_http_response_repr_handles_minimal_and_odd_values():
    r = response(headers=[], body=b'', redirect_chain=[], redirect_blocked=None, url='not a url ?q=TOKSEC')
    assert_clean(repr(r), 'minimal HttpResponse')
    assert 'redirect_blocked' not in repr(r) and '<0 headers>' in repr(r)
    odd = response(headers=None, body=None, redirect_chain=None)                              # never raises
    assert '<0 headers>' in repr(odd) and '<0 bytes>' in repr(odd)


def test_http_response_data_equality_and_helpers_are_unchanged():
    r = response()
    assert r.url == RAW_URL and r.headers == HEADERS and r.body == BODY                     # raw data intact
    assert r.header_all('set-cookie') == ['session=COOKIESEC; HttpOnly', 'csrf=COOKIE2SEC']
    assert r.header('x-api-key') == 'APIKEYSEC' and 'password=BODYPWSEC' in r.text()
    assert r == response() and r != response(status=404) and r != response(body=b'other')   # dataclass eq still compares fields
    assert [f.name for f in dataclasses.fields(HttpResponse)] == [
        'url', 'method', 'status', 'reason', 'headers', 'body', 'truncated', 'ip', 'scheme', 'tls_version', 'elapsed',
        'redirect_chain', 'redirect_blocked']
    assert dataclasses.asdict(r)['body'] == BODY                                              # internal interface untouched


# ---------------------------------------------------------------- Page / CrawlResult
def test_page_repr_is_sanitized_including_the_nested_response():
    p = Page(RAW_URL, 1, response())
    for where, text in every_form(p).items():
        assert_clean(text, f'Page {where}')
    assert 'depth=1' in repr(p) and 'HttpResponse(' in repr(p)
    assert p.url == RAW_URL and p.response.body == BODY                                      # data unchanged


def test_crawl_result_repr_shows_counts_and_codes_but_no_urls():
    c = CrawlResult(pages=[Page(RAW_URL, 0, response())],
                    skipped=[('https://x.test/a?token=TOKSEC', 'out_of_scope'), ('https://x.test/b?sig=QUERYSEC', 'out_of_scope')],
                    errors=[('https://x.test/c?sig=QUERYSEC', 'timeout')], stopped_reason='request_budget')
    for where, text in every_form(c).items():
        assert_clean(text, f'CrawlResult {where}')
    assert "pages=<1>" in repr(c) and "skipped=<2: ['out_of_scope']>" in repr(c) and "errors=<1: ['timeout']>" in repr(c)
    assert "stopped_reason='request_budget'" in repr(c)
    assert c.skipped[0][0].endswith('TOKSEC') and CrawlResult().pages == []                  # data and defaults unchanged
    assert 'pages=<0>' in repr(CrawlResult())


# ---------------------------------------------------------------- ScanOutcome / findings
def test_scan_outcome_repr_hides_the_raw_target_and_nested_findings_are_safe():
    f = build_finding('HDR-CSP-MISSING', [RAW_URL], 'GET https://a.test/ returned HTTP 200 without a header.')
    o = ScanOutcome(target='https://a.test/scan?token=TARGETSEC#frag', findings=[f], errors=['x: failed (ValueError).'],
                    notes=['note'], status='completed', pages_crawled=3, requests_used=4, checks_done=2, checks_total=2)
    for where, text in every_form(o).items():
        assert_clean(text, f'ScanOutcome {where}')
    text = repr(o)
    assert "target='https://a.test/scan?token=[redacted]'" in text and "rule_id='HDR-CSP-MISSING'" in text
    assert 'checks=2/2' in text and 'errors=<1>' in text and 'notes=<1>' in text
    assert o.target.endswith('frag') and o.errors == ['x: failed (ValueError).']             # data unchanged
    assert o.severity_counts()['Medium'] == 1


# ---------------------------------------------------------------- ValidatedTarget / ScannerConfig
def test_validated_target_repr_sanitizes_the_url_query(lab_config, resolver):
    t = validate_scan_request('http://lab.test:8080/path?token=TARGETSEC&x=1', True, lab_config, resolver)
    for where, text in every_form(t).items():
        assert_clean(text, f'ValidatedTarget {where}')
    assert "host='lab.test'" in repr(t) and 'path?token=[redacted]' in repr(t)
    assert t.url.endswith('x=1') and t.origin                                                 # raw data and properties unchanged
    assert t == dataclasses.replace(t) and hash(t) == hash(dataclasses.replace(t))            # frozen dataclass semantics kept


def test_scanner_config_never_prints_the_api_token_but_still_holds_it():
    cfg = ScannerConfig(allowlist=frozenset({'lab.test'}), lab_targets=frozenset(), api_token='TOKENVALUE-0123456789')
    for where, text in every_form(cfg).items():
        assert_clean(text, f'ScannerConfig {where}')
    assert 'api_token' not in repr(cfg) and 'lab.test' in repr(cfg)
    assert cfg.api_token == 'TOKENVALUE-0123456789'                                          # still usable internally
    assert cfg == ScannerConfig(frozenset({'lab.test'}), frozenset(), 'TOKENVALUE-0123456789')
    assert cfg != ScannerConfig(frozenset({'lab.test'}), frozenset(), 'other')               # eq still includes the token
    env = {'VULNGUARD_ALLOWED_HOSTS': 'lab.test', 'VULNGUARD_API_TOKEN': 'TOKENVALUE-0123456789'}
    loaded = load_config(env)
    assert_clean(repr(loaded), 'load_config() result')


# ---------------------------------------------------------------- end to end through the real engine
@pytest.fixture
def engine(lab_config, resolver, clock):
    def factory(target, config, resolver):
        return ScanHTTPClient(target, config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    return ScanEngine(config=lab_config, resolver=resolver, client_factory=factory)


@pytest.fixture
def capture():
    """A throw-away detector that records the real ScanContext (the registry is restored afterwards)."""
    seen = []

    class Capture(BaseDetector):
        category, name = 'cookie_security', 't-repr-capture'

        def run(self, context):
            seen.append(context)
            return []
    register(Capture)
    yield seen
    unregister('t-repr-capture')


def test_real_scan_objects_never_expose_secrets_through_repr_print_or_logging(make_server, engine, capture, caplog, capsys):
    H = [('Content-Type', 'text/html'), ('Set-Cookie', 'session=COOKIESEC; HttpOnly'),
         ('Authorization', 'Bearer HDRBEARERSEC'), ('X-Api-Key', 'APIKEYSEC')]
    page = b'<html>password=BODYPWSEC <a href="/go">g</a><a href="/p?sig=QUERYSEC&token=TOKSEC">p</a></html>'
    srv = make_server({'/': (200, H, page), '/p': (200, H, page),
                       '/go': (302, [('Location', '/p?sig=REDIRSECRET')], b'')})
    logger = logging.getLogger('repr-test')
    with caplog.at_level(logging.DEBUG):
        out = engine.run(srv.base + '/', True, {'cookie_security'})
        (ctx,) = capture
        objects = {'outcome': out, 'context': ctx, 'crawl_result': ctx.crawl_result, 'target': ctx.target,
                   'config': ctx.config, 'client': ctx.client, 'pages': ctx.pages,
                   'responses': [p.response for p in ctx.pages], 'findings': out.findings}
        for name, obj in objects.items():
            logger.info('%s: %s', name, obj)
            logger.info('%s: %r', name, obj)
            print(name, obj, [obj])
    assert out.status in ('completed', 'completed_with_errors') and len(ctx.pages) >= 2
    blobs = {'caplog': caplog.text, 'stdout': capsys.readouterr().out,
             **{f'repr({n})': repr(o) for n, o in objects.items()}}
    for where, text in blobs.items():
        assert_clean(text, where)
    # behaviour is unchanged: the real data is still there for the scanner to use
    first = ctx.pages[0].response
    assert 'session=COOKIESEC' in first.header('set-cookie') and b'password=BODYPWSEC' in first.body
    assert any('sig=QUERYSEC' in p.url for p in ctx.pages)
    assert any(len(p.response.redirect_chain) >= 1 and 'REDIRSECRET' in ' '.join(p.response.redirect_chain) for p in ctx.pages)
    assert not [r for r in caplog.records if r.name.startswith('scanner')]


def test_scan_context_repr_does_not_echo_config_or_client(lab_config, resolver):
    cfg = ScannerConfig(allowlist=frozenset({'lab.test'}), lab_targets=frozenset({'lab.test'}), api_token='TOKENVALUE-9999')
    target = validate_scan_request('http://lab.test:8080/?token=TARGETSEC', True, cfg, resolver)
    ctx = ScanContext(target=target, pages=[Page(RAW_URL, 0, response())], client=object(), config=cfg)
    for where, text in every_form(ctx).items():
        assert_clean(text, f'ScanContext {where}')
    assert 'pages=<1 pages>' in repr(ctx) and 'config' not in repr(ctx) and 'client' not in repr(ctx)
    assert ctx.config is cfg and ctx.pages[0].url == RAW_URL                                  # fields intact


# ---------------------------------------------------------------- guard: every dataclass in the package
SENSITIVE_FIELDS = {'url', 'target', 'headers', 'body', 'api_token', 'redirect_chain', 'redirect_blocked', 'skipped',
                    'errors', 'affected_urls', 'affected_url'}


def _scanner_dataclasses():
    for info in pkgutil.walk_packages(scanner.__path__, 'scanner.'):
        module = importlib.import_module(info.name)
        for _name, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ == module.__name__ and dataclasses.is_dataclass(cls):
                yield cls


def test_every_dataclass_with_a_sensitive_field_has_a_safe_representation():
    """
    Audit, codified: a dataclass whose generated repr would print a URL, header, body, token or error list must
    either define its own __repr__ or exclude that field (repr=False). New dataclasses cannot reintroduce a leak.
    """
    checked, offenders = [], []
    for cls in _scanner_dataclasses():
        sensitive = [f.name for f in dataclasses.fields(cls) if f.name in SENSITIVE_FIELDS and f.repr]
        checked.append(cls.__name__)
        if sensitive and '__repr__' not in cls.__dict__:
            offenders.append((cls.__name__, sensitive))
    assert offenders == [], f'dataclasses printing sensitive fields with the generated repr: {offenders}'
    assert {'HttpResponse', 'Page', 'CrawlResult', 'ScanOutcome', 'ScanContext', 'ValidatedTarget', 'ScannerConfig',
            'Finding'} <= set(checked)                                                      # the guard really sees them


# ---------------------------------------------------------------- asdict / vars / Flask: policy and characterization
def test_plain_json_cannot_serialize_a_finding_and_to_dict_is_the_only_serializer():
    f = build_finding('HDR-CSP-MISSING', [RAW_URL], 'ev')
    with pytest.raises(TypeError):
        json.dumps(f)                                                                      # no accidental plain-JSON path
    assert_clean(json.dumps(f.to_dict()), 'Finding.to_dict()')
    assert [n for n in dir(f) if n in ('asdict', 'to_json', 'as_dict', '__json__')] == []


def test_documented_hazard_asdict_vars_and_flask_jsonify_expose_the_internal_url_list():
    """
    Characterization of a KNOWN, deliberate limitation (see Finding's docstring). dataclasses.asdict() and vars()
    return the internal raw list, and Flask's JSON provider calls asdict() on any dataclass, so
    jsonify(finding) would serialize it. Nothing calls these today; the API layer MUST serialize with
    to_dict(). If this test ever fails because the hazard was removed, update it and the docstring.
    """
    flask = pytest.importorskip('flask')
    f = build_finding('HDR-CSP-MISSING', [RAW_URL], 'ev')
    assert 'QUERYSEC' in str(dataclasses.asdict(f)) and 'QUERYSEC' in str(vars(f))
    with flask.Flask(__name__).app_context():
        assert 'QUERYSEC' in flask.jsonify(f).get_data(as_text=True)                       # the hazard
        safe = flask.jsonify([f.to_dict()]).get_data(as_text=True)                         # the required pattern
    assert_clean(safe, 'jsonify(to_dict())')


def test_no_flask_route_serializes_scanner_objects_directly():
    """Phase 4 guard: jsonify() must receive to_dict() output, never findings/outcomes (asdict would leak URLs)."""
    risky = re.compile(r'jsonify\([^)\n]*\b(finding|findings|outcome|scan_result|result\.findings)\b(?!\.to_dict)', re.I)
    offenders = []
    for path in [ROOT / 'app.py', *(ROOT / 'routes').rglob('*.py')]:   # route code only (docstrings excluded)
        for n, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if not line.lstrip().startswith('#') and risky.search(line) and 'to_dict' not in line:
                offenders.append(f'{path.relative_to(ROOT)}:{n}: {line.strip()}')
    assert offenders == [], 'jsonify(<scanner object>) serializes via dataclasses.asdict() and exposes raw URLs; ' \
                            'use .to_dict(): ' + '; '.join(offenders)
