"""
The ONLY module in the scanner that opens network connections.

Safety properties enforced here for every request:
  * methods limited to GET / HEAD / OPTIONS; no cookies, credentials or auth headers are ever sent
  * the URL must be inside the approved scope (same host, allowlisted)
  * DNS is re-resolved and re-validated for EVERY request, and the socket connects to the
    validated IP (DNS-rebinding defence); Host header and TLS SNI keep the original name
  * redirects are followed manually, each hop re-validated; out-of-scope hops are not followed
  * per-scan request budget, rate limit, connect/read timeouts, total deadline, body size cap
  * no content decoding (Accept-Encoding: identity) so compressed-bomb responses cannot expand
"""
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from . import config as cfg
from .scope_validator import (ScopeError, ValidatedTarget, check_in_scope,
                              parse_url, resolve_and_validate)

ALLOWED_METHODS = ('GET', 'HEAD', 'OPTIONS')
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
# Headers a caller may never set: they could carry credentials or break host pinning.
_FORBIDDEN_HEADERS = {'host', 'cookie', 'authorization', 'proxy-authorization', 'connection',
                      'content-length', 'user-agent', 'accept-encoding'}


class FetchError(Exception):
    """A request failed. `kind` is machine-readable; `message` is safe to display."""

    def __init__(self, kind, message, verify_message=None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.verify_message = verify_message   # certificate verification detail, if any


class RequestBudgetExceeded(Exception):
    """The per-scan request cap was reached."""


@dataclass
class HttpResponse:
    url: str
    method: str
    status: int
    reason: str
    headers: list                      # [(name, value)] - duplicates (e.g. Set-Cookie) preserved
    body: bytes
    truncated: bool
    ip: str
    scheme: str
    tls_version: object = None         # e.g. 'TLSv1.3' for https
    elapsed: float = 0.0
    redirect_chain: list = field(default_factory=list)
    redirect_blocked: object = None    # (location, reason_code) if a redirect was NOT followed

    def header(self, name):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def content_type(self):
        return (self.header('content-type') or '').split(';')[0].strip().lower()

    def text(self):
        charset = 'utf-8'
        ct = self.header('content-type') or ''
        if 'charset=' in ct.lower():
            charset = ct.lower().split('charset=', 1)[1].split(';')[0].strip(' "\'') or 'utf-8'
        try:
            return self.body.decode(charset, errors='replace')
        except LookupError:
            return self.body.decode('utf-8', errors='replace')


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP while keeping the original host name for the Host header."""

    def __init__(self, host, port, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, pinned_ip, timeout, server_name, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._server_name = server_name

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self._server_name)
        except BaseException:
            sock.close()
            raise


class ScanHTTPClient:
    """One instance per scan; tracks the request budget and rate limit for that scan."""

    def __init__(self, origin: ValidatedTarget, config: cfg.ScannerConfig,
                 resolver=socket.getaddrinfo, clock=time.monotonic, sleep=time.sleep,
                 max_requests=cfg.MAX_REQUESTS, min_interval=cfg.MIN_REQUEST_INTERVAL):
        self.origin = origin
        self.config = config
        self._resolver = resolver
        self._clock = clock
        self._sleep = sleep
        # Callers may lower, never raise, the approved ceilings.
        self.max_requests = min(max_requests, cfg.MAX_REQUESTS)
        self.min_interval = max(min_interval, cfg.MIN_REQUEST_INTERVAL) if min_interval is not None else cfg.MIN_REQUEST_INTERVAL
        self.requests_made = 0
        self._last_request_at = None

    # -- public -----------------------------------------------------------
    def request(self, method, url, headers=None, follow_redirects=True, verify_tls=True):
        """
        Perform a request. Out-of-scope initial URLs raise ScopeError; out-of-scope redirect
        targets are not followed and are reported on the returned response.
        `verify_tls=False` exists only so passive analysis can still read a site whose
        certificate is invalid; it is never used to send anything sensitive (nothing is).
        """
        method = (method or '').upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(f'Method {method!r} is not permitted for scanning.')
        extra = self._clean_headers(headers)

        current = check_in_scope(url, self.origin, self.config)
        chain = []
        for _hop in range(cfg.MAX_REDIRECTS + 1):
            resp = self._single_request(method, current, extra, verify_tls)
            location = resp.header('location')
            if not (follow_redirects and resp.status in REDIRECT_STATUSES and location):
                resp.redirect_chain = chain
                return resp
            nxt = urljoin(current, location)
            try:
                nxt = check_in_scope(nxt, self.origin, self.config)
            except ScopeError as exc:
                resp.redirect_chain = chain
                resp.redirect_blocked = (location[:200], exc.code)
                return resp
            chain.append(nxt)
            current = nxt
        resp.redirect_chain = chain
        resp.redirect_blocked = (location[:200], 'too_many_redirects')
        return resp

    # -- internals --------------------------------------------------------
    @staticmethod
    def _clean_headers(headers):
        out = {'User-Agent': cfg.USER_AGENT,
               'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
               'Accept-Encoding': 'identity',
               'Connection': 'close'}
        for k, v in (headers or {}).items():
            if k.lower() in _FORBIDDEN_HEADERS:
                raise ValueError(f'Header {k!r} may not be set by scanner modules.')
            if any(c in f'{k}{v}' for c in '\r\n'):
                raise ValueError('Header injection attempt rejected.')
            out[k] = v
        return out

    def _throttle(self):
        now = self._clock()
        if self._last_request_at is not None:
            wait = self._last_request_at + self.min_interval - now
            if wait > 0:
                self._sleep(wait)
                now = self._clock()
        self._last_request_at = now

    def _single_request(self, method, url, headers, verify_tls):
        if self.requests_made >= self.max_requests:
            raise RequestBudgetExceeded(f'Request limit of {self.max_requests} reached.')
        # Counted before the attempt: failed and blocked attempts consume budget too.
        self.requests_made += 1
        self._throttle()

        scheme, host, port, target, _ = parse_url(url)
        # Re-resolve and re-validate right before connecting (DNS rebinding defence).
        ips, _lab = resolve_and_validate(host, port, self.config, self._resolver)

        start = self._clock()
        last_error = None
        for ip in ips:
            try:
                return self._send(method, scheme, host, port, target, ip, headers, verify_tls, start)
            except FetchError as exc:
                if exc.kind != 'connection_failed':
                    raise
                last_error = exc
        raise last_error or FetchError('connection_failed', 'Could not connect to the target.')

    def _send(self, method, scheme, host, port, target, ip, headers, verify_tls, start):
        conn_host = f'[{host}]' if ':' in host else host
        if scheme == 'https':
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = _PinnedHTTPSConnection(conn_host, port, ip, cfg.REQUEST_TIMEOUT, host, ctx)
        else:
            conn = _PinnedHTTPConnection(conn_host, port, ip, cfg.REQUEST_TIMEOUT)
        try:
            try:
                conn.request(method, target, headers=headers)
                # Must be read BEFORE getresponse(): http.client drops conn.sock for
                # non-keep-alive responses, which would lose the negotiated TLS version.
                tls_version = conn.sock.version() if scheme == 'https' and conn.sock else None
                raw = conn.getresponse()
                body, truncated = b'', False
                if method != 'HEAD':
                    body, truncated = self._read_body(raw, start)
                default_port = {'http': 80, 'https': 443}[scheme]
                port_part = '' if port == default_port else f':{port}'
                return HttpResponse(
                    url=f'{scheme}://{conn_host}{port_part}{target}',
                    method=method, status=raw.status, reason=raw.reason or '',
                    headers=list(raw.getheaders()), body=body, truncated=truncated,
                    ip=ip, scheme=scheme, tls_version=tls_version,
                    elapsed=self._clock() - start)
            except ssl.SSLCertVerificationError as exc:
                raise FetchError('tls_cert_invalid', 'TLS certificate verification failed.',
                                 verify_message=getattr(exc, 'verify_message', None))
            except ssl.SSLError:
                raise FetchError('tls_error', 'TLS handshake failed.')
            except (socket.timeout, TimeoutError):
                raise FetchError('timeout', 'The request timed out.')
            except http.client.HTTPException:
                raise FetchError('protocol_error', 'The server sent a malformed HTTP response.')
            except ConnectionError:
                raise FetchError('connection_failed', 'Could not connect to the target.')
            except OSError:
                raise FetchError('connection_failed', 'Could not connect to the target.')
        finally:
            conn.close()

    def _read_body(self, raw, start):
        """Read at most MAX_BODY_BYTES, honouring an overall deadline (slow-drip guard)."""
        chunks, total = [], 0
        while total <= cfg.MAX_BODY_BYTES:
            if self._clock() - start > cfg.REQUEST_DEADLINE:
                raise FetchError('timeout', 'The request exceeded the total time limit.')
            chunk = raw.read(min(8192, cfg.MAX_BODY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        body = b''.join(chunks)
        if len(body) > cfg.MAX_BODY_BYTES:
            return body[:cfg.MAX_BODY_BYTES], True
        return body, False
