import socket

import pytest

from scanner import config as cfg
from scanner.http_client import FetchError, RequestBudgetExceeded, ScanHTTPClient
from scanner.scope_validator import ScopeError, validate_target
from conftest import HTML, FakeResolver, page


def ok(body=b'hi'):
    return (200, {'Content-Type': 'text/plain'}, body)


def test_request_is_pinned_and_carries_only_safe_headers(make_server, make_client):
    srv = make_server({'/': ok()})
    resp = make_client(srv).request('GET', srv.base + '/')
    assert resp.status == 200 and resp.body == b'hi' and resp.ip == '127.0.0.1'
    method, path, headers = srv.seen[0]
    assert headers['host'] == f'lab.test:{srv.port}'            # original name kept despite pinned IP
    assert 'VulnGuard' in headers['user-agent']
    assert headers['accept-encoding'] == 'identity'
    assert 'cookie' not in headers and 'authorization' not in headers


def test_only_safe_methods(make_server, make_client):
    srv = make_server({'/': ok()})
    c = make_client(srv)
    for m in ('POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'):
        with pytest.raises(ValueError):
            c.request(m, srv.base + '/')
    assert srv.seen == [] and c.requests_made == 0
    assert c.request('HEAD', srv.base + '/').body == b''
    assert c.request('OPTIONS', srv.base + '/').status == 200


@pytest.mark.parametrize('name,value', [('Cookie', 'a=b'), ('Authorization', 'Bearer x'), ('Host', 'evil.test'),
                                       ('User-Agent', 'x'), ('X-Test', 'a\r\nInjected: 1')])
def test_callers_cannot_set_dangerous_headers(make_server, make_client, name, value):
    srv = make_server({'/': ok()})
    with pytest.raises(ValueError):
        make_client(srv).request('GET', srv.base + '/', headers={name: value})


def test_initial_url_out_of_scope_raises(make_server, make_client):
    srv = make_server({'/': ok()})
    c = make_client(srv)
    with pytest.raises(ScopeError):
        c.request('GET', 'http://evil.test/')
    with pytest.raises(ScopeError):
        c.request('GET', f'http://127.0.0.1:{srv.port}/')
    assert srv.seen == []


def test_in_scope_redirect_followed(make_server, make_client):
    srv = make_server({'/a': (302, {'Location': '/b'}, b''), '/c': ok()})
    srv.routes['/b'] = (301, {'Location': f'{srv.base}/c'}, b'')
    resp = make_client(srv).request('GET', srv.base + '/a')
    assert resp.status == 200 and resp.url.endswith('/c')
    assert resp.redirect_chain == [f'{srv.base}/b', f'{srv.base}/c'] and resp.redirect_blocked is None


@pytest.mark.parametrize('location', ['http://evil.test/x', 'http://127.0.0.1:{port}/x',
                                      'http://169.254.169.254/latest/meta-data/', 'https://lab.test:9/x',
                                      'ftp://lab.test/x', 'http://lab.test@evil.test/'])
def test_out_of_scope_redirect_not_followed(make_server, make_client, location, resolver):
    srv = make_server({})
    srv.routes['/r'] = (302, {'Location': location.format(port=srv.port)}, b'')
    resp = make_client(srv).request('GET', srv.base + '/r')
    assert resp.status == 302 and resp.redirect_blocked is not None
    assert srv.paths() == ['/r']                                   # nothing else was requested
    assert 'evil.test' not in resolver.calls                       # never even resolved


def test_redirect_loop_is_capped(make_server, make_client):
    srv = make_server({})
    srv.routes['/loop'] = (302, {'Location': f'{srv.base}/loop'}, b'')
    resp = make_client(srv).request('GET', srv.base + '/loop')
    assert resp.redirect_blocked[1] == 'too_many_redirects'
    assert len(srv.seen) == cfg.MAX_REDIRECTS + 1


def test_dns_rebinding_is_caught_on_next_request(make_server, lab_config, clock):
    srv = make_server({'/': ok()})
    # lookup 1 = origin validation, lookup 2 = first request: both legitimate loopback lab address;
    # afterwards DNS flips to the cloud-metadata IP (a rebinding attack)
    res = FakeResolver({'lab.test': lambda n: '127.0.0.1' if n <= 2 else '169.254.169.254'})
    origin = validate_target(srv.base + '/', lab_config, res)
    c = ScanHTTPClient(origin, lab_config, resolver=res, clock=clock.now, sleep=clock.sleep)
    assert c.request('GET', srv.base + '/').status == 200
    with pytest.raises(ScopeError) as exc:
        c.request('GET', srv.base + '/')
    assert exc.value.code == 'blocked_address'
    assert len(srv.seen) == 1


def test_request_budget_counts_every_hop_and_stops(make_server, make_client):
    srv = make_server({'/': ok()})
    srv.routes['/r'] = (302, {'Location': f'{srv.base}/'}, b'')
    c = make_client(srv, max_requests=3)
    c.request('GET', srv.base + '/r')                 # 2 requests (redirect + target)
    c.request('GET', srv.base + '/')                  # 3rd
    with pytest.raises(RequestBudgetExceeded):
        c.request('GET', srv.base + '/')
    assert c.requests_made == 3 and len(srv.seen) == 3


def test_budget_ceiling_cannot_be_raised(make_server, make_client):
    srv = make_server({'/': ok()})
    c = make_client(srv, max_requests=10_000, min_interval=0)
    assert c.max_requests == cfg.MAX_REQUESTS == 100
    assert c.min_interval >= cfg.MIN_REQUEST_INTERVAL


def test_rate_limit_spaces_requests(make_server, make_client, clock):
    srv = make_server({'/': ok()})
    c = make_client(srv)
    for _ in range(4):
        c.request('GET', srv.base + '/')
    assert len(clock.sleeps) == 3 and all(s >= cfg.MIN_REQUEST_INTERVAL - 1e-9 for s in clock.sleeps)


def test_body_is_truncated(make_server, make_client):
    srv = make_server({'/big': ok(b'A' * (cfg.MAX_BODY_BYTES + 5000)), '/small': ok(b'A' * 100)})
    c = make_client(srv)
    big = c.request('GET', srv.base + '/big')
    assert len(big.body) == cfg.MAX_BODY_BYTES and big.truncated
    small = c.request('GET', srv.base + '/small')
    assert len(small.body) == 100 and not small.truncated


def test_duplicate_headers_preserved(make_server, make_client):
    srv = make_server({'/': (200, [('Set-Cookie', 'a=1'), ('Set-Cookie', 'b=2; Secure')], b'')})
    resp = make_client(srv).request('GET', srv.base + '/')
    assert resp.header_all('set-cookie') == ['a=1', 'b=2; Secure']


def test_connection_refused_is_a_safe_error(make_client, lab_config, resolver, clock):
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    origin = validate_target(f'http://lab.test:{port}/', lab_config, resolver)
    c = ScanHTTPClient(origin, lab_config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    with pytest.raises(FetchError) as exc:
        c.request('GET', f'http://lab.test:{port}/')
    assert exc.value.kind == 'connection_failed' and '127.0.0.1' not in exc.value.message


def test_timeout(make_server, make_client, monkeypatch):
    import time
    monkeypatch.setattr(cfg, 'REQUEST_TIMEOUT', 0.3)
    srv = make_server({'/slow': lambda h: (time.sleep(1.5), ok())[1]})
    with pytest.raises(FetchError) as exc:
        make_client(srv).request('GET', srv.base + '/slow')
    assert exc.value.kind == 'timeout'


# ---- TLS: real certificates against a local HTTPS server -------------------
def test_tls_self_signed_certificate_is_reported(make_server, make_client, make_cert):
    srv = make_server({'/': ok()}, tls=make_cert('lab.test', 'lab.test'))
    c = make_client(srv)
    with pytest.raises(FetchError) as exc:
        c.request('GET', srv.base + '/')
    assert exc.value.kind == 'tls_cert_invalid' and 'self' in exc.value.verify_message.lower()
    # explicit, analysis-only opt-out still reaches the server and reports the TLS version
    resp = c.request('GET', srv.base + '/', verify_tls=False)
    assert resp.status == 200 and resp.tls_version.startswith('TLSv1')


def test_tls_hostname_mismatch_is_reported(make_server, make_client, make_cert):
    srv = make_server({'/': ok()}, tls=make_cert('other.test', 'other.test'))
    with pytest.raises(FetchError) as exc:
        make_client(srv).request('GET', srv.base + '/')
    assert exc.value.kind == 'tls_cert_invalid'
    assert 'self' in exc.value.verify_message.lower() or 'mismatch' in exc.value.verify_message.lower()


def test_tls_server_name_is_sent_not_the_ip(make_server, make_client, make_cert, monkeypatch):
    """The pinned connection must verify against the host name, never the IP it dials."""
    seen = {}
    import ssl
    orig = ssl.SSLContext.wrap_socket

    def spy(self, sock, *a, **kw):
        if kw.get('server_hostname') is not None:     # client side only (the test server also wraps)
            seen['sni'] = kw['server_hostname']
        return orig(self, sock, *a, **kw)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', spy)
    srv = make_server({'/': ok()}, tls=make_cert('lab.test', 'lab.test'))
    make_client(srv).request('GET', srv.base + '/', verify_tls=False)
    assert seen['sni'] == 'lab.test'
