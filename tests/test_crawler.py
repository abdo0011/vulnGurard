import socket

from scanner import config as cfg
from scanner.crawler import crawl, extract_links
from scanner.http_client import ScanHTTPClient
from scanner.scope_validator import validate_target
from conftest import HTML, page


def run(srv, make_client, **kw):
    client = make_client(srv, **kw.pop('client_kw', {}))
    return client, crawl(client, srv.base + '/', **kw)


def test_extract_links_filters_non_navigation():
    html = ('<a href="/a">1</a><a href="#top">2</a><a href="javascript:x()">3</a><a href="mailto:a@b.c">4</a>'
            '<a href="rel/b#frag">5</a><iframe src="/frame"></iframe><a>no href</a><a href="">e</a>'
            '<img src="/i.png"><script src="/s.js"></script><a href="/unclosed')
    assert extract_links(html, 'http://x.test/dir/') == ['http://x.test/a', 'http://x.test/dir/rel/b',
                                                         'http://x.test/frame']


def test_crawl_respects_depth_scope_and_skips(make_server, make_client):
    srv = make_server({})
    srv.routes.update({
        '/': page('/a', '/b', '/a', '/logout', '/img.png', 'http://other.test/x', f'http://127.0.0.1:{srv.port}/y',
                  '/delete?id=1', 'mailto:x@y.z', '#frag'),
        '/a': page('/c'), '/b': page(), '/c': page('/d'), '/d': page(),
    })
    client, res = run(srv, make_client)
    assert sorted(srv.paths()) == ['/', '/a', '/b', '/c']
    assert {p.depth for p in res.pages} == {0, 1, 2}
    reasons = dict(res.skipped)
    assert reasons['http://other.test/x'] == 'out_of_scope'
    assert any(r == 'skipped_path' for r in reasons.values())
    assert client.requests_made == 4                       # '/d' (depth 3) never fetched


def test_crawl_page_cap(make_server, make_client):
    srv = make_server({})
    srv.routes['/'] = page(*[f'/p{i}' for i in range(40)])
    for i in range(40):
        srv.routes[f'/p{i}'] = page()
    _client, res = run(srv, make_client)
    assert len(res.pages) == cfg.MAX_PAGES == 20 and len(srv.seen) == 20


def test_crawl_stops_at_request_budget(make_server, make_client):
    srv = make_server({})
    srv.routes['/'] = page(*[f'/p{i}' for i in range(10)])
    for i in range(10):
        srv.routes[f'/p{i}'] = page()
    client, res = run(srv, make_client, client_kw={'max_requests': 5})
    assert res.stopped_reason == 'request_budget' and len(res.pages) == 5 and len(srv.seen) == 5


def test_redirected_page_recorded_at_final_url_and_not_refetched(make_server, make_client):
    srv = make_server({})
    srv.routes['/'] = page('/old', '/new')
    srv.routes['/old'] = (302, {'Location': f'{srv.base}/new'}, b'')
    srv.routes['/new'] = page()
    _client, res = run(srv, make_client)
    assert [p.url for p in res.pages].count(f'{srv.base}/new') == 1
    assert srv.paths().count('/new') == 1


def test_non_html_is_not_parsed(make_server, make_client):
    srv = make_server({'/': (200, {'Content-Type': 'application/json'}, b'{"a": "<a href=\\"/secret\\">"}')})
    _client, res = run(srv, make_client)
    assert len(res.pages) == 1 and srv.paths() == ['/']


def test_error_pages_are_kept_but_not_followed(make_server, make_client):
    srv = make_server({'/': page('/gone'), '/gone': (404, HTML, b'<a href="/hidden">x</a>')})
    _client, res = run(srv, make_client)
    assert sorted(srv.paths()) == ['/', '/gone'] and [p.response.status for p in res.pages] == [200, 404]


def test_unreachable_start_page_returns_errors_not_exception(make_client, lab_config, resolver, clock):
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    origin = validate_target(f'http://lab.test:{port}/', lab_config, resolver)
    client = ScanHTTPClient(origin, lab_config, resolver=resolver, clock=clock.now, sleep=clock.sleep)
    res = crawl(client, f'http://lab.test:{port}/')
    assert res.pages == [] and res.errors == [(f'http://lab.test:{port}/', 'connection_failed')]
    assert client.requests_made == 1


def test_start_page_with_bad_certificate_is_still_analysed(make_server, make_client, make_cert):
    srv = make_server({'/': page()}, tls=make_cert('lab.test', 'lab.test'))
    _client, res = run(srv, make_client)
    assert len(res.pages) == 1 and res.errors[0][1] == 'tls_cert_invalid'
