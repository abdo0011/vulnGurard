"""
Scanner configuration and safety limits.

SECURITY: the numeric limits below are deliberately module constants, NOT
environment-configurable, so a misconfiguration can never raise them above the
approved ceilings. Only the *scope* (allowlist, lab targets) and the API token are
read from the environment.
"""
import hmac
import ipaddress
import os
from dataclasses import dataclass, field

# ---- hard safety ceilings (approved in Phase 1/2 review) -------------------
MAX_DEPTH = 2                 # crawl depth: start page = 0, links from depth 2 are not followed
MAX_PAGES = 20                # pages fetched by the crawler
MAX_REQUESTS = 100            # every outbound HTTP request of a scan, incl. redirect hops
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10.0        # seconds, per socket operation
REQUEST_DEADLINE = 30.0       # seconds, total wall-clock for a single request (slow-drip guard)
MAX_BODY_BYTES = 512 * 1024   # response bodies are truncated beyond this
MIN_REQUEST_INTERVAL = 0.5    # seconds between requests => at most 2 requests/second
USER_AGENT = 'VulnGuard-Scanner/1.0 (authorized security assessment)'

ENV_ALLOWLIST = 'VULNGUARD_SCAN_ALLOWLIST'   # approved target hosts, comma separated
ENV_LAB_TARGETS = 'VULNGUARD_LAB_TARGETS'    # hosts explicitly allowed to resolve to private/loopback
ENV_API_TOKEN = 'VULNGUARD_API_TOKEN'
ENV_HOST = 'VULNGUARD_HOST'

MIN_TOKEN_LENGTH = 16


class ConfigError(Exception):
    """Invalid or unsafe configuration. Messages are safe to show to the operator."""


def _split_entry(entry):
    """'host' / 'host:port' / '[v6]' / '[v6]:port' -> (host, port-or-None)."""
    if entry.startswith('['):
        end = entry.find(']')
        if end == -1:
            raise ConfigError(f"Malformed host entry: {entry!r}")
        host, rest = entry[1:end], entry[end + 1:]
        if rest and not rest.startswith(':'):
            raise ConfigError(f"Malformed host entry: {entry!r}")
        port = rest[1:] if rest else None
    elif entry.count(':') == 1:
        host, port = entry.split(':')
    elif ':' in entry:
        raise ConfigError(f"IPv6 literals must be written in brackets: {entry!r}")
    else:
        host, port = entry, None
    return host, port


def normalize_entry(entry):
    """
    Normalize one allowlist/lab entry to 'host' or 'host:port'.
    Wildcards, URLs, paths and CIDR ranges are refused on purpose: scope is an
    explicit list of hosts, never a pattern.
    """
    entry = entry.strip().lower()
    if not entry:
        return None
    if any(c in entry for c in ('*', '/', '\\', '@', ' ', '?', '#')) or '://' in entry:
        raise ConfigError(f"Invalid scope entry {entry!r}: use exact hosts (optionally host:port), no wildcards or URLs.")
    host, port = _split_entry(entry)
    if not host:
        raise ConfigError(f"Invalid scope entry {entry!r}.")
    try:
        host = str(ipaddress.ip_address(host))
        is_ip = True
    except ValueError:
        is_ip = False
        try:
            host = host.rstrip('.').encode('idna').decode('ascii')
        except UnicodeError:
            raise ConfigError(f"Invalid host in scope entry {entry!r}.")
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ConfigError(f"Invalid port in scope entry {entry!r}.")
        host = f'[{host}]' if is_ip and ':' in host else host
        return f'{host}:{int(port)}'
    return host


def _parse_list(raw):
    entries = set()
    for part in (raw or '').split(','):
        norm = normalize_entry(part)
        if norm:
            entries.add(norm)
    return frozenset(entries)


@dataclass(frozen=True)
class ScannerConfig:
    allowlist: frozenset          # approved target hosts (every scan must match)
    lab_targets: frozenset        # subset allowed to resolve to loopback/private ranges
    api_token: object = field(default=None, repr=False)      # str or None; a credential: never part of repr()


def load_config(env=None):
    """Read scope settings from the environment (re-read on every scan; nothing is cached)."""
    env = os.environ if env is None else env
    token = env.get(ENV_API_TOKEN) or None
    return ScannerConfig(
        allowlist=_parse_list(env.get(ENV_ALLOWLIST)),
        lab_targets=_parse_list(env.get(ENV_LAB_TARGETS)),
        api_token=token,
    )


def is_loopback_host(host):
    host = (host or '').strip().lower()
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host.strip('[]')).is_loopback
    except ValueError:
        return False


def check_network_binding(host, debug=False, token=None):
    """
    Refuse unsafe server configurations.
    Loopback binding needs nothing. Any other bind address (reachable from the network)
    requires an API token of reasonable length, and may never run in debug mode (the
    Werkzeug debugger allows remote code execution).
    """
    if is_loopback_host(host):
        return
    if not token or len(token) < MIN_TOKEN_LENGTH:
        raise ConfigError(
            f"Refusing to listen on {host!r}: network access requires {ENV_API_TOKEN} "
            f"(at least {MIN_TOKEN_LENGTH} characters).")
    if debug:
        raise ConfigError("Refusing to run in debug mode while listening on a non-loopback address.")


def verify_api_token(config, provided):
    """Constant-time token comparison. Returns True when no token is configured (loopback mode)."""
    if not config.api_token:
        return True
    return bool(provided) and hmac.compare_digest(str(provided).encode(), config.api_token.encode())
