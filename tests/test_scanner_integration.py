"""
Phase 4: scanner integration with the Flask application.

Nothing here contacts an external host: scans run against LocalServer instances on 127.0.0.1 (conftest) reached through
a fake resolver, and the Flask app uses a throw-away SQLite file per test.
"""
import hashlib
import json
import sqlite3
import threading

import pytest

import app as vg
import scan_service
from scanner.config import ScannerConfig
from scanner.engine import ScanOutcome
from scanner.models import Finding
from scanner.scope_validator import ScopeError
from tests.conftest import FakeResolver, page

SECRET = 'S3CRETVALUE9'


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def flask_app(tmp_path, monkeypatch, lab_config, resolver):
    monkeypatch.setattr(vg, 'DB_PATH', str(tmp_path / 'test.db'))
    vg.init_db()
    monkeypatch.setattr(vg, 'scan_manager', scan_service.ScanManager())
    vg.app.config.update(TESTING=True, SCAN_CONFIG=lab_config, SCAN_RESOLVER=resolver, SCAN_ENGINE_FACTORY=None)
    yield vg
    vg.scan_manager.join(30)
    for key in ('SCAN_CONFIG', 'SCAN_RESOLVER', 'SCAN_ENGINE_FACTORY'):
        vg.app.config.pop(key, None)


@pytest.fixture
def client(flask_app):
    return flask_app.app.test_client()


def seed(conn=None):
    with vg.db() as c:
        c.execute("INSERT INTO assets (name, ip_address, asset_type, created_date) VALUES ('web-01', '10.0.0.5', 'Website', '2026-01-01')")
        c.execute("INSERT INTO assets (name, ip_address, asset_type, created_date) VALUES ('db-01', '', 'Database', '2026-01-01')")
        c.execute("INSERT INTO vulnerabilities (title, description, severity, status, asset, cvss_score, discovered_date, updated_date, asset_id) "
                  "VALUES ('Old bug', 'd', 'High', 'Open', 'web-01', 7.5, '2026-01-02', '2026-01-02', 1)")
        c.execute("INSERT INTO vulnerabilities (title, description, severity, status, asset, cvss_score, discovered_date, updated_date, asset_id) "
                  "VALUES ('Legacy', 'd', 'Low', 'Fixed', 'db-01', 2.0, '2026-01-03', '2026-01-03', 2)")


def digest():
    with vg.db() as c:
        out = []
        for t in ('assets', 'vulnerabilities'):
            out.append(hashlib.sha256(repr([tuple(r) for r in c.execute(f'select * from {t} order by id')]).encode()).hexdigest())
        return out


def rows(sql, *params):
    with vg.db() as c:
        return [dict(r) for r in c.execute(sql, params)]


def post(client, payload, **kw):
    return client.post('/api/scans', json=payload, **kw)


def run_scan(client, flask_app, payload):
    r = post(client, payload)
    assert r.status_code == 202, r.get_json()
    flask_app.scan_manager.join(30)
    return r.get_json()['id']


class FakeEngine:
    """Records its calls; `behaviour(url, categories, progress)` returns a ScanOutcome or raises."""

    def __init__(self, behaviour=None):
        self.calls = []
        self.behaviour = behaviour

    def run(self, url, authorized, categories=None, progress=None):
        self.calls.append((url, authorized, categories))
        if progress:
            progress('crawling', 1, 4, 0)
        if self.behaviour:
            return self.behaviour(url, categories, progress)
        return ScanOutcome(target=url, status='completed', stage='done', checks_done=4, checks_total=4,
                           started_at='2026-11-16 22:00:00', completed_at='2026-11-16 22:00:05')


def use_engine(flask_app, engine):
    flask_app.app.config['SCAN_ENGINE_FACTORY'] = lambda config, resolver: engine
    return engine


def finding(sev='High', title='Missing header', evidence='evidence', url='https://lab.test/page?x=1'):
    return Finding(rule_id='HDR-TEST', title=title, category='security_headers', severity=sev, confidence='Confirmed',
                   description='desc', affected_urls=[url], evidence=evidence, impact='impact', remediation='fix it',
                   reference='REF', detection_method='Passive')


TARGET = 'http://lab.test:8080/'
OK = {'target': TARGET, 'authorized': True}


# ---------------------------------------------------------------- page and options
def test_the_scanner_page_is_part_of_the_existing_dashboard(client):
    html = client.get('/').get_data(as_text=True)
    assert 'id="nav-scanner"' in html and 'href="#scanner"' in html and 'id="view-scanner"' in html
    assert 'id="nav-dashboard"' in html and 'id="nav-assets"' in html and 'id="view-assets"' in html   # nothing removed
    assert client.get('/static/scanner.js').status_code == 200


def test_scanner_js_loads_before_app_js_because_app_js_routes_on_load(client):
    html = client.get('/').get_data(as_text=True)
    assert html.index('scanner.js') < html.index('app.js')       # app.js calls route() -> initScannerView() at startup


def test_options_list_the_implemented_detectors_assets_and_limits(client):
    seed()
    data = client.get('/api/scanner/options').get_json()
    assert {c['id'] for c in data['categories']} == {'security_headers', 'cookie_security', 'ssl_tls'}
    assert [a['name'] for a in data['assets']] == ['db-01', 'web-01']
    assert data['limits']['max_requests'] == 100 and data['allowlist_configured'] is True and data['busy'] is False


# ---------------------------------------------------------------- input validation
@pytest.mark.parametrize('payload', [
    {}, {'authorized': True}, {'target': '', 'authorized': True}, {'target': 5, 'authorized': True},
    {'target': ['a'], 'authorized': True}, {'target': 'x' * 3000, 'authorized': True}])
def test_a_missing_or_malformed_target_is_rejected(client, flask_app, payload):
    r = post(client, payload)
    assert r.status_code == 400 and flask_app.scan_manager.is_busy() is False
    assert rows('select * from scans') == []


def test_the_body_must_be_a_json_object(client):
    assert client.post('/api/scans', data='target=http://lab.test/', content_type='application/x-www-form-urlencoded').status_code == 400
    assert client.post('/api/scans', json=['http://lab.test/']).status_code == 400


@pytest.mark.parametrize('categories', [[], 'security_headers', ['nope'], ['security_headers', 5], ['information_disclosure'], {'a': 1}])
def test_invalid_categories_are_rejected(client, categories):
    r = post(client, {**OK, 'categories': categories})
    assert r.status_code == 400 and r.get_json()['code'] == 'invalid_categories'


@pytest.mark.parametrize('asset_id,status', [('abc', 400), (True, 400), (1.5, 400), (999, 404)])
def test_an_invalid_asset_is_rejected(client, asset_id, status):
    seed()
    assert post(client, {**OK, 'asset_id': asset_id}).status_code == status


# ---------------------------------------------------------------- authorization and scope
@pytest.mark.parametrize('authorized', [None, False, 'true', 'yes', 1, 0, [], 'on'])
def test_a_scan_needs_explicit_boolean_authorization(client, flask_app, authorized):
    engine = use_engine(flask_app, FakeEngine())
    payload = {'target': TARGET} if authorized is None else {'target': TARGET, 'authorized': authorized}
    r = post(client, payload)
    assert r.status_code == 400 and r.get_json()['code'] == 'authorization_required'
    assert engine.calls == [] and rows('select * from scans') == []


@pytest.mark.parametrize('target,code,status', [
    ('http://not-approved.test/', 'host_not_allowlisted', 403),
    ('http://example.com/', 'host_not_allowlisted', 403),
    ('http://127.0.0.1/', 'host_not_allowlisted', 403),
    ('http://169.254.169.254/latest/meta-data/', 'host_not_allowlisted', 403),
    ('ftp://lab.test/', 'scheme_not_allowed', 400),
    ('file:///etc/passwd', 'scheme_not_allowed', 400),
    ('http://user:pw@lab.test/', 'credentials_in_url', 400),
    ('http://2130706433/', 'invalid_host', 400),
    ('not a url', 'invalid_url', 400)])
def test_out_of_scope_and_malformed_targets_are_rejected_before_any_scan(client, flask_app, target, code, status):
    engine = use_engine(flask_app, FakeEngine())
    r = post(client, {'target': target, 'authorized': True})
    assert (r.status_code, r.get_json()['code']) == (status, code)
    assert engine.calls == [] and rows('select * from scans') == []


def test_an_empty_allowlist_refuses_every_target(client, flask_app):
    flask_app.app.config['SCAN_CONFIG'] = ScannerConfig(allowlist=frozenset(), lab_targets=frozenset())
    r = post(client, OK)
    assert r.status_code == 403 and 'VULNGUARD_SCAN_ALLOWLIST' in r.get_json()['error']


def test_unapproved_hosts_are_never_resolved(client, flask_app):
    resolver = FakeResolver({'lab.test': '127.0.0.1'})
    flask_app.app.config['SCAN_RESOLVER'] = resolver
    assert post(client, {'target': 'http://not-approved.test/', 'authorized': True}).status_code == 403
    assert resolver.calls == []


def test_a_hostname_resolving_to_an_internal_address_is_blocked_without_echoing_the_address(client, flask_app):
    config = ScannerConfig(allowlist=frozenset({'sneaky.test'}), lab_targets=frozenset())      # allowlisted but NOT a lab target
    flask_app.app.config['SCAN_CONFIG'] = config
    flask_app.app.config['SCAN_RESOLVER'] = FakeResolver({'sneaky.test': '10.20.30.40'})
    r = post(client, {'target': 'http://sneaky.test/', 'authorized': True})
    assert r.status_code == 403 and r.get_json()['code'] == 'blocked_address'
    assert '10.20.30.40' not in r.get_data(as_text=True)
    assert rows('select * from scans') == []


def test_cloud_metadata_addresses_stay_blocked_even_for_lab_targets(client, flask_app):
    flask_app.app.config['SCAN_CONFIG'] = ScannerConfig(allowlist=frozenset({'meta.test'}), lab_targets=frozenset({'meta.test'}))
    flask_app.app.config['SCAN_RESOLVER'] = FakeResolver({'meta.test': '169.254.169.254'})
    r = post(client, {'target': 'http://meta.test/', 'authorized': True})
    assert r.status_code == 403 and '169.254' not in r.get_data(as_text=True)


# ---------------------------------------------------------------- engine invocation (mock)
def test_the_scanner_engine_is_invoked_with_the_authorised_target_and_categories(client, flask_app):
    engine = use_engine(flask_app, FakeEngine())
    scan_id = run_scan(client, flask_app, {**OK, 'categories': ['ssl_tls', 'security_headers', 'ssl_tls']})
    assert engine.calls == [(TARGET, True, ['security_headers', 'ssl_tls'])]       # canonical order, de-duplicated
    scan = client.get(f'/api/scans/{scan_id}').get_json()
    assert scan['status'] == 'completed' and scan['categories'] == ['security_headers', 'ssl_tls']


def test_all_categories_are_used_by_default(client, flask_app):
    engine = use_engine(flask_app, FakeEngine())
    run_scan(client, flask_app, OK)
    assert engine.calls[0][2] == ['security_headers', 'cookie_security', 'ssl_tls']


# ---------------------------------------------------------------- results and persistence (mock)
def test_findings_are_persisted_grouped_and_ordered_by_severity(client, flask_app):
    def behaviour(url, categories, progress):
        return ScanOutcome(target=url, status='completed', stage='done', checks_done=4, checks_total=4, pages_crawled=3,
                           requests_used=5, started_at='2026-11-16 22:00:00', completed_at='2026-11-16 22:00:09',
                           findings=[finding('Low', 'low one'), finding('Critical', 'crit one'), finding('High', 'high one'),
                                     finding('High', 'high two'), finding('Informational', 'info one')])
    use_engine(flask_app, FakeEngine(behaviour))
    scan_id = run_scan(client, flask_app, OK)
    scan = client.get(f'/api/scans/{scan_id}').get_json()
    assert scan['findings_total'] == 5 and scan['pages_crawled'] == 3 and scan['requests_used'] == 5
    assert scan['severity_counts'] == {'Critical': 1, 'High': 2, 'Medium': 0, 'Low': 1, 'Informational': 1}
    assert [f['severity'] for f in scan['findings']] == ['Critical', 'High', 'High', 'Low', 'Informational']
    f = scan['findings'][0]
    for key in ('title', 'description', 'urls', 'evidence', 'remediation', 'impact', 'reference',
                'category_label', 'confidence', 'rule_id'):
        assert f[key]
    assert f['urls'] == ['https://lab.test/page?x=[redacted]']                      # sanitized: query values removed
    assert f['category_label'] == 'Security Headers'
    assert scan['started_at'] == '2026-11-16 22:00:00' or scan['started_at']          # recorded by the app when the scan starts
    assert scan['completed_at'] == '2026-11-16 22:00:09'
    assert len(rows('select * from scan_findings where scan_id = ?', scan_id)) == 5


def test_stored_and_returned_data_is_sanitised_and_redacted(client, flask_app):
    def behaviour(url, categories, progress):
        return ScanOutcome(target=url, status='completed', stage='done', findings=[
            finding(evidence=f'cookie is password={SECRET} on https://lab.test/p?token={SECRET}',
                    url=f'https://lab.test/p?token={SECRET}')])
    use_engine(flask_app, FakeEngine(behaviour))
    scan_id = run_scan(client, flask_app, {'target': f'http://lab.test:8080/?session={SECRET}', 'authorized': True})
    body = client.get(f'/api/scans/{scan_id}').get_data(as_text=True) + client.get('/api/scans').get_data(as_text=True)
    stored = json.dumps(rows('select * from scans') + rows('select * from scan_findings'))
    assert SECRET not in body and SECRET not in stored


def test_progress_is_recorded_while_the_scan_runs(client, flask_app):
    release, reached = threading.Event(), threading.Event()

    def behaviour(url, categories, progress):
        progress('analysing', 2, 4, 1)
        reached.set()
        release.wait(10)
        return ScanOutcome(target=url, status='completed', stage='done')
    use_engine(flask_app, FakeEngine(behaviour))
    r = post(client, OK)
    assert r.status_code == 202
    assert reached.wait(10)
    scan = client.get(f"/api/scans/{r.get_json()['id']}").get_json()
    assert scan['status'] == 'running' and scan['stage'] == 'analysing' and scan['checks_done'] == 2
    release.set()
    flask_app.scan_manager.join(30)
    assert client.get(f"/api/scans/{r.get_json()['id']}").get_json()['status'] == 'completed'


def test_unknown_scan_ids_return_404(client):
    assert client.get('/api/scans/9999').status_code == 404


# ---------------------------------------------------------------- duplicate submissions
def test_a_second_scan_cannot_start_while_one_is_running(client, flask_app):
    release, reached = threading.Event(), threading.Event()

    def behaviour(url, categories, progress):
        reached.set()
        release.wait(10)
        return ScanOutcome(target=url, status='completed', stage='done')
    engine = use_engine(flask_app, FakeEngine(behaviour))
    first = post(client, OK)
    assert first.status_code == 202 and reached.wait(10)
    for _ in range(3):                                                           # repeated submissions
        again = post(client, OK)
        assert again.status_code == 409 and again.get_json()['code'] == 'scan_in_progress'
    assert client.get('/api/scanner/options').get_json()['busy'] is True
    release.set()
    flask_app.scan_manager.join(30)
    assert len(engine.calls) == 1 and len(rows('select * from scans')) == 1
    assert post(client, OK).status_code == 202                                   # free again afterwards
    flask_app.scan_manager.join(30)
    assert len(rows('select * from scans')) == 2


# ---------------------------------------------------------------- error handling
def test_an_unexpected_engine_error_fails_the_scan_safely_and_frees_the_slot(client, flask_app):
    def boom(url, categories, progress):
        raise RuntimeError(f'internal detail {SECRET} at /srv/app/secret.py')
    use_engine(flask_app, FakeEngine(boom))
    scan_id = run_scan(client, flask_app, OK)
    text = client.get(f'/api/scans/{scan_id}').get_data(as_text=True)
    scan = json.loads(text)
    assert scan['status'] == 'failed' and scan['errors'] == ['The scan failed unexpectedly (RuntimeError).']
    assert SECRET not in text and '/srv/app' not in text
    assert flask_app.scan_manager.is_busy() is False
    use_engine(flask_app, FakeEngine())
    assert post(client, OK).status_code == 202


def test_a_scope_error_raised_by_the_engine_is_reported_without_internal_addresses(client, flask_app):
    def rejected(url, categories, progress):
        raise ScopeError('blocked_address', 'host resolves to a non-public or reserved address (10.9.8.7)')
    use_engine(flask_app, FakeEngine(rejected))
    scan = client.get(f'/api/scans/{run_scan(client, flask_app, OK)}').get_json()
    assert scan['status'] == 'failed' and '10.9.8.7' not in json.dumps(scan)
    assert 'non-public or reserved' in scan['errors'][0]


def test_engine_errors_and_notes_are_stored_for_completed_with_errors(client, flask_app):
    def behaviour(url, categories, progress):
        return ScanOutcome(target=url, status='completed_with_errors', stage='done', errors=['cookie-security: failed (ValueError).'],
                           notes=['Crawl stopped: request limit reached.'])
    use_engine(flask_app, FakeEngine(behaviour))
    scan = client.get(f'/api/scans/{run_scan(client, flask_app, OK)}').get_json()
    assert scan['status'] == 'completed_with_errors'
    assert scan['errors'] == ['cookie-security: failed (ValueError).'] and scan['notes'] == ['Crawl stopped: request limit reached.']


def test_a_failure_while_storing_results_still_frees_the_slot(client, flask_app, monkeypatch):
    use_engine(flask_app, FakeEngine())
    monkeypatch.setattr(scan_service, 'save_outcome', lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError('disk')))
    scan = client.get(f'/api/scans/{run_scan(client, flask_app, OK)}').get_json()
    assert scan['status'] == 'failed' and 'OperationalError' in scan['errors'][0]
    assert flask_app.scan_manager.is_busy() is False


# ---------------------------------------------------------------- API token
def test_scanner_routes_require_the_api_token_when_one_is_configured(client, flask_app):
    flask_app.app.config['SCAN_CONFIG'] = ScannerConfig(allowlist=frozenset({'lab.test'}), lab_targets=frozenset({'lab.test'}),
                                                         api_token='t' * 20)
    use_engine(flask_app, FakeEngine())
    for call in (lambda h: client.get('/api/scanner/options', headers=h), lambda h: client.get('/api/scans', headers=h),
                 lambda h: client.get('/api/scans/1', headers=h), lambda h: client.post('/api/scans', json=OK, headers=h)):
        for headers in ({}, {'X-API-Token': 'wrong'}):
            r = call(headers)
            assert r.status_code == 401 and r.get_json()['code'] == 'token_required'
    assert rows('select * from scans') == []
    assert client.post('/api/scans', json=OK, headers={'X-API-Token': 't' * 20}).status_code == 202


# ---------------------------------------------------------------- existing data
def test_scans_and_findings_never_alter_existing_assets_and_vulnerabilities(client, flask_app):
    seed()
    before = digest()
    def behaviour(url, categories, progress):
        return ScanOutcome(target=url, status='completed', stage='done', findings=[finding()])
    use_engine(flask_app, FakeEngine(behaviour))
    run_scan(client, flask_app, {**OK, 'asset_id': 1})
    assert digest() == before
    assert client.get('/api/vulnerabilities').status_code == 200 and len(client.get('/api/vulnerabilities').get_json()) == 2
    stats = client.get('/api/stats').get_json()
    assert stats['total'] == 2 and stats['total_assets'] == 2


def test_a_scan_is_linked_to_an_existing_asset(client, flask_app):
    seed()
    use_engine(flask_app, FakeEngine())
    scan_id = run_scan(client, flask_app, {**OK, 'asset_id': 2})
    assert client.get(f'/api/scans/{scan_id}').get_json()['asset_name'] == 'db-01'
    assert client.get('/api/scans').get_json()['scans'][0]['asset_name'] == 'db-01'


def test_deleting_an_asset_keeps_its_scans(client, flask_app):
    with vg.db() as c:
        c.execute("INSERT INTO assets (name, asset_type, created_date) VALUES ('lonely', 'Other', '2026-01-01')")
    use_engine(flask_app, FakeEngine())
    scan_id = run_scan(client, flask_app, {**OK, 'asset_id': 1})
    assert client.delete('/api/assets/1').status_code == 200
    scan = client.get(f'/api/scans/{scan_id}').get_json()
    assert scan['asset_id'] is None and scan['status'] == 'completed'


def test_the_migration_is_additive_idempotent_and_keeps_legacy_data(tmp_path, monkeypatch):
    path = str(tmp_path / 'legacy.db')
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, '
                 'severity TEXT NOT NULL, status TEXT NOT NULL, asset TEXT, cvss_score REAL, discovered_date TEXT, updated_date TEXT)')
    conn.execute("INSERT INTO vulnerabilities (title, severity, status, asset) VALUES ('Legacy finding', 'High', 'Open', 'old-host')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(vg, 'DB_PATH', path)
    vg.init_db()
    vg.init_db()                                                                   # running twice changes nothing
    with vg.db() as c:
        tables = {r[0] for r in c.execute("select name from sqlite_master where type = 'table'")}
        assert {'assets', 'vulnerabilities', 'scans', 'scan_findings'} <= tables
        v = c.execute('select title, severity, asset, asset_id from vulnerabilities').fetchall()
        assert len(v) == 1 and v[0]['title'] == 'Legacy finding' and v[0]['asset_id'] is not None
        assert c.execute('select count(*) from assets').fetchone()[0] == 1


def test_stale_running_scans_are_closed_but_a_fresh_one_is_not(flask_app):
    with vg.db() as c:
        c.execute("INSERT INTO scans (target, status, stage, started_at, created_date) VALUES ('http://old/', 'running', 'crawling', '2020-01-01 00:00:00', '2020-01-01 00:00:00')")
        c.execute("INSERT INTO scans (target, status, stage, started_at, created_date) VALUES ('http://new/', 'running', 'crawling', ?, ?)",
                  (scan_service.now_str(), scan_service.now_str()))
    vg.init_db()
    states = {r['target']: r['status'] for r in rows('select target, status from scans')}
    assert states == {'http://old/': 'failed', 'http://new/': 'running'}


# ---------------------------------------------------------------- real scanner, controlled local target
def test_a_real_scan_of_a_local_lab_target_completes_and_shows_results(client, flask_app, make_server):
    seed()
    before = digest()
    cookie = ('Set-Cookie', 'sid=' + SECRET + '; Path=/')
    server = make_server({'/': lambda h: (200, [('Content-Type', 'text/html; charset=utf-8'), cookie], b'<html><body><a href="/two">two</a></body></html>'),
                          '/two': page()})
    r = post(client, {'target': server.base + f'/?token={SECRET}', 'authorized': True, 'asset_id': 1})
    assert r.status_code == 202
    flask_app.scan_manager.join(60)
    scan = client.get(f"/api/scans/{r.get_json()['id']}").get_json()
    assert scan['status'] in ('completed', 'completed_with_errors') and scan['errors'] == []
    assert scan['pages_crawled'] == 2 and scan['asset_name'] == 'web-01'
    rule_ids = {f['rule_id'] for f in scan['findings']}
    assert 'HDR-CSP-MISSING' in rule_ids                                           # Security Headers detector ran
    assert {'COOKIE-NO-HTTPONLY#sid', 'COOKIE-SAMESITE-MISSING#sid'} <= rule_ids  # Cookie Security detector ran (rule ids carry the cookie name)
    assert {f['category'] for f in scan['findings']} <= {'security_headers', 'cookie_security', 'ssl_tls'}
    assert scan['findings_total'] == len(scan['findings']) and sum(scan['severity_counts'].values()) == len(scan['findings'])
    assert all(f['remediation'] and f['evidence'] and f['description'] for f in scan['findings'])
    everything = json.dumps(scan) + client.get('/api/scans').get_data(as_text=True) + json.dumps(rows('select * from scan_findings'))
    assert SECRET not in everything and '127.0.0.1' not in everything             # no cookie value, query secret or resolved IP
    assert digest() == before
    assert server.seen and all(p.split('?')[0] in ('/', '/two') for p in server.paths())   # only the lab target was contacted


def test_a_real_scan_limited_to_one_category_only_runs_that_detector(client, flask_app, make_server):
    server = make_server({'/': lambda h: (200, [('Content-Type', 'text/html'), ('Set-Cookie', 'sid=1')], b'<html></html>')})
    scan_id = run_scan(client, flask_app, {'target': server.base + '/', 'authorized': True, 'categories': ['cookie_security']})
    scan = client.get(f'/api/scans/{scan_id}').get_json()
    assert scan['findings'] and {f['category'] for f in scan['findings']} == {'cookie_security'}


def test_a_real_scan_of_an_unreachable_target_reports_a_failure(client, flask_app):
    scan_id = run_scan(client, flask_app, {'target': 'http://lab.test:1/', 'authorized': True})       # nothing listens on port 1
    scan = client.get(f'/api/scans/{scan_id}').get_json()
    assert scan['status'] == 'failed' and scan['errors'] and scan['findings'] == []


# ---------------------------------------------------------------- invalid scanner configuration (environment variables)
BAD_ENTRIES = ['http://lab.test:8080', '*.lab.test', '::1', 'lab.test/path', 'user@lab.test', 'lab.test:99999', 'lab.test:abc',
               'lab.test:', '[::1', '10.0.0.0/8']


@pytest.fixture
def env_config(flask_app, monkeypatch):
    """Make the app read its scope from the environment (as in production) instead of the injected test config."""
    flask_app.app.config['SCAN_CONFIG'] = None
    for name in ('VULNGUARD_SCAN_ALLOWLIST', 'VULNGUARD_LAB_TARGETS', 'VULNGUARD_API_TOKEN'):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def assert_safe_config_error(response, bad_value):
    assert response.status_code == 400                                    # a clear client error, not a 500
    body = response.get_json()
    assert body['code'] == 'invalid_scanner_config' and body['error'] == vg.INVALID_SCAN_CONFIG_MESSAGE
    text = response.get_data(as_text=True)
    assert bad_value not in text                                           # the offending value is not echoed
    for leak in ('Traceback', 'ConfigError', '.py', 'File "'):
        assert leak not in text


@pytest.mark.parametrize('bad', BAD_ENTRIES)
def test_an_invalid_allowlist_is_a_clear_client_error_for_the_options_route(client, env_config, bad):
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', bad)
    assert_safe_config_error(client.get('/api/scanner/options'), bad)


@pytest.mark.parametrize('bad', BAD_ENTRIES)
def test_an_invalid_allowlist_stops_a_scan_before_anything_is_created(client, flask_app, env_config, bad):
    engine = use_engine(flask_app, FakeEngine())
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', bad)
    assert_safe_config_error(post(client, OK), bad)
    assert engine.calls == [] and rows('select * from scans') == [] and flask_app.scan_manager.is_busy() is False


@pytest.mark.parametrize('bad', BAD_ENTRIES)
def test_an_invalid_lab_target_list_is_rejected_the_same_way(client, flask_app, env_config, bad):
    engine = use_engine(flask_app, FakeEngine())
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', 'lab.test')
    env_config.setenv('VULNGUARD_LAB_TARGETS', f'lab.test, {bad}')
    assert_safe_config_error(client.get('/api/scanner/options'), bad)
    assert_safe_config_error(post(client, OK), bad)
    assert engine.calls == [] and rows('select * from scans') == []


def test_every_scanner_route_handles_an_invalid_configuration(client, env_config):
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', 'http://lab.test')
    for response in (client.get('/api/scanner/options'), client.get('/api/scans'), client.get('/api/scans/1'),
                     client.post('/api/scans', json=OK)):
        assert_safe_config_error(response, 'http://lab.test')


def test_the_error_does_not_reveal_the_api_token_or_the_value(client, env_config):
    env_config.setenv('VULNGUARD_API_TOKEN', 'TOKEN-' + 'x' * 20)
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', '*.internal.corp')
    response = client.get('/api/scanner/options')
    assert_safe_config_error(response, 'internal.corp')
    assert 'TOKEN-' not in response.get_data(as_text=True)


def test_the_rest_of_the_application_is_unaffected_by_an_invalid_scanner_configuration(client, env_config):
    seed()
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', '*.bad')
    assert client.get('/').status_code == 200
    assert len(client.get('/api/vulnerabilities').get_json()) == 2 and client.get('/api/stats').get_json()['total_assets'] == 2


@pytest.mark.parametrize('allowlist,lab', [
    ('lab.test', 'lab.test'), ('lab.test:8080', 'lab.test:8080'), ('LAB.test , other.test:443', 'lab.test'),
    ('127.0.0.1:8000', '127.0.0.1:8000'), ('[::1]:5000', '[::1]:5000'), ('lab.test', '')])
def test_a_valid_configuration_from_the_environment_still_works(client, flask_app, env_config, allowlist, lab):
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', allowlist)
    env_config.setenv('VULNGUARD_LAB_TARGETS', lab)
    options = client.get('/api/scanner/options')
    assert options.status_code == 200 and options.get_json()['allowlist_configured'] is True
    assert client.get('/api/scans').status_code == 200


def test_a_scan_runs_with_a_valid_environment_configuration(client, flask_app, env_config):
    engine = use_engine(flask_app, FakeEngine())
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', 'lab.test:8080')
    env_config.setenv('VULNGUARD_LAB_TARGETS', 'lab.test:8080')
    scan_id = run_scan(client, flask_app, OK)
    assert engine.calls and client.get(f'/api/scans/{scan_id}').get_json()['status'] == 'completed'


def test_an_unset_scope_is_not_a_configuration_error_but_still_refuses_every_target(client, flask_app, env_config):
    assert client.get('/api/scanner/options').get_json()['allowlist_configured'] is False
    r = post(client, OK)
    assert r.status_code == 403 and r.get_json()['code'] == 'host_not_allowlisted'


def test_a_valid_allowlist_entry_does_not_widen_scope(client, flask_app, env_config):
    engine = use_engine(flask_app, FakeEngine())
    env_config.setenv('VULNGUARD_SCAN_ALLOWLIST', 'lab.test:8080')
    for target in ('http://lab.test:9999/', 'http://other.test:8080/'):
        r = post(client, {'target': target, 'authorized': True})
        assert r.status_code == 403 and r.get_json()['code'] == 'host_not_allowlisted'
    assert engine.calls == []
