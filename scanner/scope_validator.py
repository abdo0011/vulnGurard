"""
Target validation: the gatekeeper every scan request and every outbound request passes.

Threats handled here: SSRF (internal/metadata addresses), DNS rebinding (re-resolution is
validated each time and the client connects to the validated IP), URL parser tricks
(credentials, backslashes, numeric/octal/hex IP forms), scope escape through redirects,
and scanning hosts nobody approved.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .config import ScannerConfig
from .sanitize import sanitize_url

DEFAULT_PORTS = {'http': 80, 'https': 443}
MAX_URL_LENGTH = 2048

_HOST_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')

# IPv6 transition ranges that can smuggle an IPv4 address past naive checks.
_BLOCKED_V6_NETS = [ipaddress.ip_network(n) for n in
                    ('64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32')]


class ScopeError(Exception):
    """A target or request is outside the allowed scope. `code` is machine-readable."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, repr=False)
class ValidatedTarget:
    url: str            # normalized URL (no fragment, no credentials)
    scheme: str
    host: str           # lowercase, IDNA-encoded, no brackets
    port: int
    ips: tuple          # validated destination addresses (strings)
    is_lab: bool = False

    def __repr__(self):                 # representation only: the URL may still carry a query string
        return (f'ValidatedTarget(url={sanitize_url(self.url)!r}, scheme={self.scheme!r}, host={self.host!r}, '
                f'port={self.port!r}, ips={self.ips!r}, is_lab={self.is_lab!r})')

    @property
    def origin(self):
        return f'{self.scheme}://{_host_for_url(self.host)}{_port_suffix(self.scheme, self.port)}'


def _host_for_url(host):
    return f'[{host}]' if ':' in host else host


def _port_suffix(scheme, port):
    return '' if DEFAULT_PORTS.get(scheme) == port else f':{port}'


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------
def parse_url(raw):
    """Strictly parse and normalize an http(s) URL. Returns (scheme, host, port, path_and_query, url)."""
    raw = (raw or '').strip() if isinstance(raw, str) else ''
    if not raw or len(raw) > MAX_URL_LENGTH:
        raise ScopeError('invalid_url', 'A valid URL is required (max 2048 characters).')
    # Control chars, whitespace and backslashes are classic parser-differential tricks.
    if any(ord(c) <= 32 or ord(c) == 127 or c == '\\' for c in raw):
        raise ScopeError('invalid_url', 'URL contains illegal characters.')
    try:
        parts = urlsplit(raw)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise ScopeError('invalid_url', 'URL could not be parsed.')

    scheme = (parts.scheme or '').lower()
    if scheme not in DEFAULT_PORTS:
        raise ScopeError('scheme_not_allowed', 'Only http:// and https:// URLs are allowed.')
    if parts.username is not None or parts.password is not None or '@' in parts.netloc:
        raise ScopeError('credentials_in_url', 'URLs containing credentials are not allowed.')
    if not host:
        raise ScopeError('invalid_host', 'URL has no host.')
    if port is not None and not 1 <= port <= 65535:
        raise ScopeError('invalid_url', 'Invalid port.')
    port = port or DEFAULT_PORTS[scheme]

    host = _normalize_host(host)
    path = parts.path or '/'
    target = path + (f'?{parts.query}' if parts.query else '')
    url = urlunsplit((scheme, _host_for_url(host) + _port_suffix(scheme, port), path, parts.query, ''))
    return scheme, host, port, target, url


def _normalize_host(host):
    host = host.lower().rstrip('.')
    try:
        return str(ipaddress.ip_address(host))      # literal IPv4/IPv6 (zone ids are rejected)
    except ValueError:
        pass
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError:
        raise ScopeError('invalid_host', 'Invalid host name.')
    if len(host) > 253 or not _HOST_RE.match(host):
        raise ScopeError('invalid_host', 'Invalid host name.')
    # Forms like 2130706433, 127.1, 0x7f.0.0.1 or 0177.0.0.1 are resolved by libc as IPv4 but are
    # not valid IP literals for Python: refuse them outright instead of guessing.
    last = host.rsplit('.', 1)[-1]
    if last.isdigit() or last.startswith('0x'):
        raise ScopeError('invalid_host', 'Ambiguous numeric host; use a host name or a standard IP address.')
    return host


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------
def classify_ip(ip):
    """
    Return 'public', 'private' (loopback / RFC1918 / ULA: lab-eligible) or 'blocked' (never allowed).
    Link-local (cloud metadata 169.254.169.254), multicast, unspecified, reserved, carrier-grade
    NAT and IPv6 transition ranges are always blocked, even for lab targets.
    """
    ip = ipaddress.ip_address(ip)
    if ip.version == 6:
        if ip.ipv4_mapped:                      # ::ffff:127.0.0.1 must be judged as 127.0.0.1
            ip = ip.ipv4_mapped
        elif any(ip in net for net in _BLOCKED_V6_NETS):
            return 'blocked'
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return 'blocked'
    # Loopback is judged BEFORE 'reserved': Python reports ::1 as reserved (::/8), but it is a
    # legitimate, lab-eligible loopback address. Other ::/8 addresses stay blocked below.
    if ip.is_loopback:
        return 'private'
    if ip.is_reserved:
        return 'blocked'
    if ip.is_global:
        return 'public'
    if ip.is_private:
        # 100.64.0.0/10 (shared address space) is neither global nor private: falls through to blocked.
        return 'private'
    return 'blocked'


def _entry_matches(entries, host, port):
    h = f'[{host}]' if ':' in host else host
    return host in entries or h in entries or f'{h}:{port}' in entries


def check_allowlist(host, port, config: ScannerConfig):
    if not config.allowlist:
        raise ScopeError('host_not_allowlisted',
                         'No approved scan targets are configured. Set VULNGUARD_SCAN_ALLOWLIST to the hosts you are authorized to test.')
    if not _entry_matches(config.allowlist, host, port):
        raise ScopeError('host_not_allowlisted', f'{host} is not on the approved target allowlist.')


def resolve_and_validate(host, port, config: ScannerConfig, resolver=socket.getaddrinfo):
    """
    Resolve `host` and validate EVERY returned address. Returns (ips, is_lab).
    A single blocked address rejects the host (defends against mixed-record rebinding).
    Private/loopback addresses are accepted only for hosts explicitly listed as lab targets.
    """
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            infos = resolver(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError):
            raise ScopeError('dns_failure', f'Could not resolve {host}.')
        ips = []
        for info in infos:
            addr = info[4][0].split('%')[0]
            if addr not in ips:
                ips.append(addr)
    if not ips:
        raise ScopeError('dns_failure', f'Could not resolve {host}.')

    is_lab = False
    for ip in ips:
        kind = classify_ip(ip)
        if kind == 'public':
            continue
        if kind == 'private' and _entry_matches(config.lab_targets, host, port):
            is_lab = True
            continue
        raise ScopeError('blocked_address',
                         f'{host} resolves to a non-public or reserved address ({ip}), which is not allowed.')
    return tuple(ips), is_lab


def validate_target(url, config: ScannerConfig, resolver=socket.getaddrinfo):
    """Parse -> allowlist -> DNS -> address validation. Returns a ValidatedTarget or raises ScopeError."""
    scheme, host, port, _target, normalized = parse_url(url)
    check_allowlist(host, port, config)          # before DNS: unapproved hosts are never even resolved
    ips, is_lab = resolve_and_validate(host, port, config, resolver)
    return ValidatedTarget(normalized, scheme, host, port, ips, is_lab)


def validate_scan_request(url, authorized, config: ScannerConfig, resolver=socket.getaddrinfo):
    """Entry point for starting a scan: explicit authorization attestation + full target validation."""
    if authorized is not True:                   # strictly boolean True: "true"/1/"yes" do not count
        raise ScopeError('authorization_required',
                         'You must confirm that you are authorized to test this target.')
    return validate_target(url, config, resolver)


# ---------------------------------------------------------------------------
# Redirect / crawl scope
# ---------------------------------------------------------------------------
def check_in_scope(url, origin: ValidatedTarget, config: ScannerConfig):
    """
    Cheap (no DNS) scope test for a candidate URL such as a redirect Location or crawled link.
    In scope = same host as the approved target, still on the allowlist, http(s) only, and the
    port is either the original port or the default port of the candidate's scheme (so an
    http->https upgrade of the same host is fine, a hop to another port/host is not).
    Returns the normalized URL; raises ScopeError otherwise.
    """
    scheme, host, port, _t, normalized = parse_url(url)
    if host != origin.host:
        raise ScopeError('out_of_scope', 'URL is outside the approved target scope.')
    if port not in (origin.port, DEFAULT_PORTS[scheme]):
        raise ScopeError('out_of_scope', 'URL uses a port outside the approved target scope.')
    check_allowlist(host, port, config)
    return normalized
