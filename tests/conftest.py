"""
Shared fixtures. All network traffic in tests goes to servers started here on 127.0.0.1;
host names such as lab.test are mapped to loopback by a fake resolver, so nothing external
is ever contacted.
"""
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanner.config import ScannerConfig
from scanner.http_client import ScanHTTPClient
from scanner.scope_validator import validate_target


class FakeClock:
    """Deterministic clock: sleep() just advances time, so rate-limit tests are instant."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


class FakeResolver:
    """getaddrinfo stand-in. mapping: host -> ip, list of ips, or a callable(call_number)->ips."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, host, port, type=0, **kwargs):
        self.calls.append(host)
        if host not in self.mapping:
            raise socket.gaierror(socket.EAI_NONAME, 'unknown host')
        value = self.mapping[host]
        if callable(value):
            value = value(len([c for c in self.calls if c == host]))
        ips = [value] if isinstance(value, str) else value
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port))
                for ip in ips]


class LocalServer:
    def __init__(self, routes, tls=None):
        self.routes = routes
        self.seen = []            # [(method, path, {lower-case header: value})]
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def _handle(self):
                outer.seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
                route = outer.routes.get(self.path.split('#')[0]) or outer.routes.get(self.path.split('?')[0])
                if route is None:
                    route = (404, {'Content-Type': 'text/html'}, b'not found')
                if callable(route):
                    route = route(self)
                status, headers, body = route
                if isinstance(headers, dict):
                    headers = list(headers.items())
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                if self.command != 'HEAD':
                    self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if self.command != 'HEAD':
                    try:
                        self.wfile.write(body)
                    except OSError:
                        pass

            do_GET = do_HEAD = do_OPTIONS = _handle

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = 'https' if tls else 'http'
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return f'{self.scheme}://lab.test:{self.port}'

    def paths(self):
        return [p for _m, p, _h in self.seen]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


HTML = {'Content-Type': 'text/html; charset=utf-8'}


def page(*links, extra=''):
    body = ''.join(f'<a href="{l}">x</a>' for l in links) + extra
    return (200, HTML, f'<html><body>{body}</body></html>'.encode())


@pytest.fixture
def lab_config():
    """lab.test is allowlisted AND an explicit lab target (so it may resolve to loopback)."""
    return ScannerConfig(allowlist=frozenset({'lab.test'}), lab_targets=frozenset({'lab.test'}))


@pytest.fixture
def resolver():
    return FakeResolver({'lab.test': '127.0.0.1'})


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def make_server():
    servers = []

    def _make(routes, tls=None):
        s = LocalServer(routes, tls)
        servers.append(s)
        return s

    yield _make
    for s in servers:
        s.stop()


@pytest.fixture
def make_client(lab_config, resolver, clock):
    def _make(server, **kw):
        origin = validate_target(server.base + '/', lab_config, resolver)
        return ScanHTTPClient(origin, lab_config, resolver=resolver, clock=clock.now, sleep=clock.sleep, **kw)
    return _make


@pytest.fixture(scope='session')
def make_cert(tmp_path_factory):
    """Generate a self-signed certificate (requires the openssl CLI)."""
    if not shutil.which('openssl'):
        pytest.skip('openssl CLI not available')
    cache = {}

    def _make(cn, san):
        if (cn, san) not in cache:
            d = tmp_path_factory.mktemp('cert')
            key, crt = str(d / 'k.pem'), str(d / 'c.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                            '-out', crt, '-days', '2', '-subj', f'/CN={cn}',
                            '-addext', f'subjectAltName=DNS:{san}'],
                           check=True, capture_output=True)
            cache[(cn, san)] = (crt, key)
        return cache[(cn, san)]
    return _make
