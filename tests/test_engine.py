import os
import socket
import subprocess
import sys

import pytest

from scanner.detectors import BaseDetector, get_detectors, register, unregister
from scanner.engine import ScanEngine
from scanner.http_client import ScanHTTPClient
from scanner.models import Finding
from scanner.scope_validator import ScopeError
from conftest import page


def finding(rule, url, **kw):
    kw.setdefault('evidence', 'ev')
    return Finding(rule_id=rule, title=rule, category='security_headers', severity='Low', confidence='Confirmed',
                   description='d', affected_urls=[url], impact='i', remediation='r', reference='ref',
                   detection_method='test', **kw)


@pytest.fixture
def detectors():
    """Register throw-away detectors for one test and remove them afterwards."""
    added = []

    def add(cls):
        added.append(cls.name)
        return register(cls)
    yield add
    for name in added:
        unregister(name)


@pytest.fixture
def engine(lab_config, resolver, clock):
    def factory(target, config, resolver):
        return ScanHTTPClient(target, config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    return ScanEngine(config=lab_config, resolver=resolver, client_factory=factory)


def test_registry_rejects_unknown_category_and_filters(detectors):
    class A(BaseDetector):
        category, name = 'security_headers', 't-a'
        def run(self, ctx): return []

    class B(BaseDetector):
        category, name = 'cookie_security', 't-b'
        def run(self, ctx): return []
    detectors(A); detectors(B)
    assert {d.name for d in get_detectors({'security_headers'})} == {'t-a'}
    assert {d.name for d in get_detectors()} == {'t-a', 't-b'}
    with pytest.raises(ValueError):
        get_detectors({'nope'})

    class Bad(BaseDetector):
        category, name = 'invalid', 't-bad'
    with pytest.raises(ValueError):
        register(Bad)


def test_engine_end_to_end(make_server, engine, detectors):
    srv = make_server({})
    srv.routes['/'] = page('/a', '/b', extra='password=hunter2hunter2')
    srv.routes['/a'] = page(); srv.routes['/b'] = page()

    class Dup(BaseDetector):                 # reports the same site-wide issue on every page -> must dedupe
        category, name = 'security_headers', 't-dup'
        def run(self, ctx):
            return [finding('RULE-1', p.url, evidence='password=hunter2hunter2') for p in ctx.pages]
    detectors(Dup)

    events = []
    out = engine.run(srv.base + '/', True, progress=lambda *a: events.append(a))
    assert out.status == 'completed' and not out.errors
    assert out.pages_crawled == 3 and out.requests_used == len(srv.seen) == 3
    assert len(out.findings) == 1 and len(out.findings[0].affected_urls) == 3
    assert 'hunter2' not in out.findings[0].evidence                     # redacted before it leaves the engine
    assert out.severity_counts()['Low'] == 1
    # progress reports real counters, ends complete
    assert [e[0] for e in events][:2] == ['validating', 'crawling'] and events[-1][0] == 'done'
    assert out.checks_done == out.checks_total == 2 and events[-1][3] == 1


def test_rejections_happen_before_any_request(make_server, engine, resolver):
    srv = make_server({'/': page()})
    with pytest.raises(ScopeError) as e:
        engine.run(srv.base + '/', False)
    assert e.value.code == 'authorization_required'
    with pytest.raises(ScopeError) as e:
        engine.run('http://other.test/', True)
    assert e.value.code == 'host_not_allowlisted'
    with pytest.raises(ScopeError):
        engine.run('file:///etc/passwd', True)
    with pytest.raises(ValueError):
        engine.run(srv.base + '/', True, categories={'bogus'})
    assert srv.seen == [] and 'other.test' not in resolver.calls


def test_failing_detector_is_isolated_and_error_is_sanitized(make_server, engine, detectors):
    srv = make_server({'/': page()})

    class Boom(BaseDetector):
        category, name = 'security_headers', 't-boom'
        def run(self, ctx): raise RuntimeError('db password is hunter2 at /srv/internal/path')

    class Fine(BaseDetector):
        category, name = 'cookie_security', 't-fine'
        def run(self, ctx): return [finding('RULE-OK', ctx.pages[0].url)]

    class Junk(BaseDetector):
        category, name = 'ssl_tls', 't-junk'
        def run(self, ctx): return ['not a finding', {'x': 1}]
    for d in (Boom, Fine, Junk):
        detectors(d)
    out = engine.run(srv.base + '/', True)
    assert out.status == 'completed_with_errors' and [f.rule_id for f in out.findings] == ['RULE-OK']
    joined = ' '.join(out.errors)
    assert 'RuntimeError' in joined and 'hunter2' not in joined and '/srv/' not in joined
    assert out.checks_done == out.checks_total


def test_detector_cannot_escape_scope_through_the_client(make_server, engine, detectors, resolver):
    srv = make_server({'/': page()})

    class Escape(BaseDetector):
        category, name = 'security_configuration', 't-escape'
        def run(self, ctx):
            ctx.client.request('GET', 'http://evil.test/')
            return []
    detectors(Escape)
    out = engine.run(srv.base + '/', True)
    assert 'ScopeError' in ' '.join(out.errors) and 'evil.test' not in resolver.calls


def test_category_selection_limits_detectors(make_server, engine, detectors):
    srv = make_server({'/': page()})
    ran = []

    class H(BaseDetector):
        category, name = 'security_headers', 't-h'
        def run(self, ctx): ran.append('h'); return []

    class C(BaseDetector):
        category, name = 'cookie_security', 't-c'
        def run(self, ctx): ran.append('c'); return []
    detectors(H); detectors(C)
    out = engine.run(srv.base + '/', True, categories={'cookie_security'})
    assert ran == ['c'] and out.checks_total == 2


def test_unreachable_target_fails_cleanly_without_running_detectors(engine, lab_config, detectors):
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    ran = []

    class D(BaseDetector):
        category, name = 'security_headers', 't-d'
        def run(self, ctx): ran.append(1); return []
    detectors(D)
    out = engine.run(f'http://lab.test:{port}/', True)
    assert out.status == 'failed' and ran == [] and out.findings == []
    assert 'connection_failed' in out.errors[0] and '127.0.0.1' not in out.errors[0]
    assert out.completed_at and out.stage == 'done'


def test_request_budget_is_enforced_for_detectors_too(make_server, engine, detectors):
    srv = make_server({'/': page()})

    class Greedy(BaseDetector):
        category, name = 'security_configuration', 't-greedy'
        def run(self, ctx):
            for _ in range(500):
                ctx.client.request('GET', ctx.target.url)
            return []
    detectors(Greedy)
    out = engine.run(srv.base + '/', True)
    assert out.requests_used == 100 and len(srv.seen) == 100
    assert any('request limit' in n for n in out.notes)


# ---- network-binding guard in app.py ---------------------------------------
def _run_app(tmp_path, **env):
    full = {**os.environ, 'VULNGUARD_DB': str(tmp_path / 't.db'), **env}
    for k in ('VULNGUARD_HOST', 'VULNGUARD_API_TOKEN', 'FLASK_DEBUG'):
        if k not in env:
            full.pop(k, None)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return subprocess.run([sys.executable, 'app.py'], cwd=root, env=full, capture_output=True, text=True, timeout=10)


def test_app_refuses_network_binding_without_token(tmp_path):
    r = _run_app(tmp_path, VULNGUARD_HOST='0.0.0.0')
    assert r.returncode != 0 and 'VULNGUARD_API_TOKEN' in r.stderr


def test_app_refuses_debug_on_network_even_with_token(tmp_path):
    r = _run_app(tmp_path, VULNGUARD_HOST='0.0.0.0', VULNGUARD_API_TOKEN='t' * 32, FLASK_DEBUG='1')
    assert r.returncode != 0 and 'debug' in r.stderr.lower()
