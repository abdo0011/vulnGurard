"""
SSL/TLS detector (passive).

It makes NO request and no handshake of its own. It reads only what the crawler's ordinary HTTPS requests already
produced, which is exactly two things:

  * the TLS version negotiated on each HTTPS response (HttpResponse.tls_version), and
  * the reason a certificate was refused (CrawlResult.tls_failures: OpenSSL's verification error NUMBER and message,
    recorded by the crawler when the standard, verifying handshake failed).

Everything below follows from that, and nothing else is inferred.

Reported
  * Expired / not yet valid / host name mismatch / self-signed certificate: the verifier named the exact problem
    (X509_V_ERR_CERT_HAS_EXPIRED, ..._NOT_YET_VALID, ..._HOSTNAME_MISMATCH and ..._IP_ADDRESS_MISMATCH,
    ..._DEPTH_ZERO_SELF_SIGNED_CERT), so these are Confirmed.
  * Chain / issuer problems (OpenSSL errors 2, 19, 20, 21): Potential. They say that OpenSSL could not build a
    trusted chain, not WHY: an unknown issuer, a missing intermediate certificate and a scanner trust store that lacks
    the root all produce them, and the verdict is the scanner host's trust store's, which can differ from a client's.
    The evidence states what OpenSSL reports and hedges the possible causes.
  * Any other verifier error: TLS-CERT-INVALID, Confirmed that validation failed, with OpenSSL's own message.
  * An obsolete protocol (SSLv2/SSLv3/TLS 1.0/TLS 1.1) negotiated on a live connection: Confirmed. The version comes
    from the connection itself.
  * TLS-LEGACY-UNTESTED (an Informational limitation note) once per host that negotiated TLS 1.2 or 1.3: the scanner's
    own client refuses TLS 1.0/1.1, so servers that still accept them cannot be told apart from servers that do not.

Deliberately NOT reported (the existing infrastructure cannot observe it reliably, and absence of evidence is never a
finding): certificate expiry dates for valid certificates (TLS-CERT-EXPIRING-SOON needs the peer certificate, which is
not collected), weak ciphers or key sizes, certificate chain details, revocation, and legacy protocol acceptance. A
handshake that fails for any other reason (kind 'tls_error') is not attributable to a cause and produces no finding.
Only the FIRST verification error is reported by OpenSSL, so other problems may also exist (an expired certificate
can hide a host name mismatch); evidence says so.

Evidence contains the host name and port the scanner requested (sanitized), the verification error number and
OpenSSL's fixed message, and the negotiated protocol version. It never contains certificate contents (subject,
issuer, serial, fingerprints, keys), IP addresses of the server, or response bodies.

Findings are collected per rule and host:port, so a site-wide problem is ONE finding listing the affected URLs.

Input validation: a record is used only if its URL is a well-formed HTTPS URL (scheme in any case) with a valid host
name (strict RFC 1123, no underscores) or IP literal and a valid port. Anything else (http, ftp, javascript, schemeless, malformed, no host, invalid
port, control characters, oversized) produces nothing. The endpoint key and the URL stored in the finding are rebuilt
from the validated host and port: user names and passwords are dropped before anything is stored, so they cannot
appear in extra, evidence, serialized findings, representations, fingerprints or grouping.
"""
import ipaddress
import re
from collections import namedtuple
from itertools import islice
from urllib.parse import urlsplit, urlunsplit

from ..rules import build_finding
from ..sanitize import sanitize_url
from . import BaseDetector, register

OBSOLETE_VERSIONS = ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1')
# Each obsolete version is cited against the document that actually covers it. RFC 8996 deprecates TLS 1.0 and TLS 1.1
# ONLY; SSL 3.0 and SSL 2.0 are covered by RFC 7568 and RFC 6176.
_OBSOLETE_NOTE = {'TLSv1': 'TLS 1.0, deprecated by RFC 8996', 'TLSv1.1': 'TLS 1.1, deprecated by RFC 8996',
                  'SSLv3': 'SSL 3.0, prohibited by RFC 7568', 'SSLv2': 'SSL 2.0, prohibited by RFC 6176'}
MODERN_VERSIONS = ('TLSv1.2', 'TLSv1.3')
MAX_FAILURES = 200                    # bound on the failures examined (the crawler's own page/request caps apply first)
MAX_MESSAGE_CHARS = 120
MAX_REASONS_SHOWN = 6                 # distinct reasons listed in one finding's evidence (the rest are counted)
MAX_URLS_PER_REASON = 3               # URLs listed per reason (the rest are counted)

# OpenSSL X509_V_ERR_* number -> (rule, confidence, plain-language reason). Numbers are stable across OpenSSL 1.1/3.x.
_VERIFY = {
    10: ('TLS-CERT-EXPIRED', 'Confirmed', 'the certificate has expired'),
    9: ('TLS-CERT-NOT-YET-VALID', 'Confirmed', 'the certificate is not yet valid'),
    62: ('TLS-CERT-HOSTNAME-MISMATCH', 'Confirmed', 'the certificate is not valid for the requested host name'),
    64: ('TLS-CERT-HOSTNAME-MISMATCH', 'Confirmed', 'the certificate is not valid for the requested IP address'),
    18: ('TLS-CERT-SELF-SIGNED', 'Confirmed', 'the certificate is self-signed'),
    # Chain / issuer problems. Each text says what OpenSSL REPORTS; likely causes are hedged ("may", "commonly") because the
    # verifier does not say whether the server, the scanner host's trust store, or both are at fault.
    19: ('TLS-CERT-UNTRUSTED', 'Potential', 'OpenSSL reports a self-signed certificate in the certificate chain that '
                                          'is not in the scanner host\'s trust store (this does not by itself show '
                                          'whether it is a private root or a misconfiguration)'),
    20: ('TLS-CERT-UNTRUSTED', 'Potential', 'OpenSSL could not find the issuer certificate of a certificate in the '
                                          'chain in the scanner host\'s trust store or in the chain the server sent '
                                          '(the cause may be an unknown issuer, a missing intermediate certificate, '
                                          'or a trust store without the issuing root)'),
    21: ('TLS-CERT-UNTRUSTED', 'Potential', 'OpenSSL could not verify the first certificate: the chain it had contained only '
                                          'that one certificate, which is not self-signed, so no signature could be '
                                          'checked (commonly the server sent no intermediate certificate and the '
                                          'issuer is not in the scanner host\'s trust store; the exact cause is not '
                                          'established)'),
    2: ('TLS-CERT-UNTRUSTED', 'Potential', 'OpenSSL could not obtain the issuer certificate of a certificate in the '
                                         'chain (an issuer problem; whether the server or the scanner host\'s trust '
                                         'store is at fault is not established)'),
}
_TRUST_CAVEAT = (' This is a verdict of the scanner host\'s trust store, which can differ from the stores clients use.')
_FIRST_ERROR = (' OpenSSL reports only the first problem it finds, so further problems may exist.')


MAX_URL_CHARS = 2048
DEFAULT_HTTPS_PORT = 443
_LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')          # RFC 1123 label; the same rule as Phase 2's scope validator


def _valid_hostname(host):
    """
    Host name policy: strict RFC 1123, the same label rule as Phase 2's scope validator (scope_validator._HOST_RE).
    ASCII only, at most 253 characters, labels of 1-63 letters, digits and inner hyphens; NO underscores (so
    'lab_host.test' is rejected, as it is for a scan target); no empty labels. IPv4 and IPv6 literals are handled by the
    caller and keep working.

    Numeric hosts: a last label that is all digits or starts with '0x' is rejected. This MIRRORS Phase 2, whose
    scope_validator._normalize_host() applies the same check after _HOST_RE ("ambiguous numeric host": forms like
    2130706433, 127.1, 0x7f.0.0.1 or a.0x7f, which libc may resolve as IPv4). It is not an extra restriction of this
    detector. Compared with Phase 2's effective rule this function is equal for ASCII, lower-case names; the only
    differences are in _endpoint() and are stricter (it strips ONE trailing dot where Phase 2 strips all, and it does not
    convert non-ASCII names with IDNA but rejects them). A test pins the equivalence.
    """
    if not host or len(host) > 253 or not host.isascii():
        return False
    labels = host.split('.')
    # Same "ambiguous numeric host" rule as scope_validator._normalize_host: a digit-only or 0x-prefixed last label is
    # a malformed or non-standard IPv4 form (1.2.3.4.5, 127.1, a.0x7f), never a real top-level domain.
    last = labels[-1]
    return all(_LABEL.match(label) for label in labels) and not (last.isdigit() or last.startswith('0x'))


def _explicit_empty_port(netloc):
    """
    True for a ':' that introduces no port ('a.test:', '[::1]:', 'user@a.test:'). urlsplit().port returns None for it,
    exactly as for a URL with no port at all, so the difference has to be read from the netloc. Three cases are kept
    apart: no ':' (no explicit port: HTTPS default 443), ':<digits>' (explicit port, range-checked by urlsplit) and a
    bare ':' (malformed: rejected). Text after a bracketed IPv6 literal that is not ':<port>' is rejected as well.
    """
    hostport = netloc.rpartition('@')[2]
    if hostport.startswith('['):
        tail = hostport[hostport.find(']') + 1:]
        return tail != '' and (not tail.startswith(':') or tail == ':')
    return hostport.endswith(':')


def _endpoint(url):
    """
    Validate `url` as an HTTPS URL and return (key, host, port, clean_url), or None for anything else.

    key is the canonical endpoint 'host' or 'host:port' ('[v6]:port' for IPv6; the default port 443 is omitted), built
    ONLY from the validated host name and port, never from the raw netloc, so user names and passwords cannot reach
    finding metadata and cannot split findings. Port policy: no ':' means the default 443; ':<1-65535>' is an explicit
    port; a bare ':' (empty port), ':0', a non-numeric or out-of-range port are invalid and yield None. clean_url is the URL rebuilt on that key without user info or fragment
    (the query is kept: it is part of a page's identity and is redacted by the output guard).
    """
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        return None
    if any(ch.isspace() or ch == '\\' or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return None                                                  # control characters, spaces, backslashes
    try:
        parts = urlsplit(url)
        port = parts.port                                            # ValueError for a non-numeric or out-of-range port
    except ValueError:
        return None
    if parts.scheme.lower() != 'https' or not parts.netloc or not parts.hostname:
        return None                                                  # not HTTPS (http, ftp, javascript, '//host/...') or no host
    if port == 0 or _explicit_empty_port(parts.netloc):
        return None
    host = parts.hostname.lower()
    try:
        host = str(ipaddress.ip_address(host))                       # canonical IPv4 / IPv6
        if '%' in host:
            return None                                              # an IPv6 zone identifier is not a routable host name
    except ValueError:
        if '%' in host or ':' in host:
            return None                                              # a malformed IPv6 literal or zone id is not a host name
        host = host[:-1] if host.endswith('.') else host
        if not _valid_hostname(host):
            return None
    port = None if port in (None, DEFAULT_HTTPS_PORT) else port
    bracketed = f'[{host}]' if ':' in host else host
    key = f'{bracketed}:{port}' if port else bracketed
    clean = urlunsplit(('https', key, parts.path or '/', parts.query, ''))
    return key, host, port, clean


def _label(host, port):
    host = f'[{host}]' if ':' in host else host
    return f'{host}:{port}' if port else host


_Render = namedtuple('_Render', 'single multi tail')   # how one finding's evidence is worded (see _Collector.findings)


class _Collector:
    """
    Groups records into ONE finding per (rule, endpoint). Each record carries a REASON (the part of the explanation that
    differs between records, e.g. OpenSSL error 19 versus 20, or TLS 1.0 versus 1.1). Records are kept per reason, so
    every distinct reason stays attributed to exactly the URLs it was observed on; nothing is dropped because it came
    second. Evidence is built from sorted reasons and sorted URLs, so it does not depend on crawl order.
    """

    def __init__(self):
        self.items = {}               # (rule_id, endpoint key) -> {'urls', 'reasons', 'confidence', 'render', 'seq'}

    def add(self, rule_id, key, url, reason, render, confidence='Confirmed'):
        sort_key, text = reason
        entry = self.items.get((rule_id, key))
        if entry is None:
            entry = self.items[(rule_id, key)] = {'urls': [], 'reasons': {}, 'confidence': confidence, 'render': render,
                                                  'seq': len(self.items)}
        if url not in entry['urls']:
            entry['urls'].append(url)                      # every unique affected URL, first-seen order
        info = entry['reasons'].setdefault(text, {'sort': sort_key, 'urls': []})
        if url not in info['urls']:
            info['urls'].append(url)

    def findings(self):
        out = []
        for (rule_id, key), e in sorted(self.items.items(), key=lambda item: item[1]['seq']):
            reasons = sorted(e['reasons'].items(), key=lambda item: (item[1]['sort'], item[0]))
            render = e['render']
            if len(reasons) == 1:
                text, info = reasons[0]
                evidence = render.single(text, min(info['urls'])) + render.tail
                if len(info['urls']) > 1:
                    evidence += f' {len(info["urls"])} requests to this host:port showed this.'
            else:
                lines = []
                for number, (text, info) in enumerate(reasons[:MAX_REASONS_SHOWN], 1):
                    urls = sorted(info['urls'])
                    shown = ', '.join(sanitize_url(u) for u in urls[:MAX_URLS_PER_REASON])
                    if len(urls) > MAX_URLS_PER_REASON:
                        shown += f' and {len(urls) - MAX_URLS_PER_REASON} more'
                    lines.append(f'({number}) {text}: {shown}.')
                unlisted = len(reasons) - MAX_REASONS_SHOWN
                evidence = (render.multi(len(reasons)) + render.tail + ' ' + ' '.join(lines)
                            + (f' {unlisted} more reason(s) not listed.' if unlisted > 0 else ''))
            out.append(build_finding(rule_id, sorted(e['urls']), evidence, confidence=e['confidence'], extra={'host': key}))
        return out


def _message(text):
    """OpenSSL's fixed verification message, bounded and reduced to printable ASCII."""
    if not isinstance(text, str):
        return ''
    return ''.join(ch if ' ' <= ch <= '~' else '?' for ch in text[:MAX_MESSAGE_CHARS]).strip()


@register
class TlsSecurityDetector(BaseDetector):
    category = 'ssl_tls'
    name = 'tls-security'

    def run(self, context):
        # Error handling is deliberately absent (see cookie_security.run): the inputs are data produced by our own
        # client and crawler and are validated by type below; an exception here is a bug, and ScanEngine reports it.
        found = _Collector()
        self._certificate_failures(found, getattr(getattr(context, 'crawl_result', None), 'tls_failures', None) or [])
        self._protocol_versions(found, context.pages)
        return found.findings()

    @staticmethod
    def _certificate_failures(found, failures):
        for item in islice(failures, MAX_FAILURES):             # bounded without materialising the whole list
            if not (isinstance(item, (tuple, list)) and len(item) == 3 and isinstance(item[0], str)):
                continue                                           # malformed record: no evidence, no finding
            url, code, message = item
            endpoint = _endpoint(url)
            if endpoint is None:
                continue                                           # not a valid HTTPS URL: no evidence, no finding
            key, host, port, url = endpoint                        # from here on only the credential-free canonical URL
            label = _label(host, port)
            has_code = isinstance(code, int) and not isinstance(code, bool)
            known = _VERIFY.get(code) if has_code else None
            if known:
                rule_id, confidence, reason = known
                text = f'{reason} (OpenSSL verification error {code})'
            else:
                rule_id, confidence = 'TLS-CERT-INVALID', 'Confirmed'
                detail = _message(message)
                number = f'verification error {code}' if has_code else 'verification error number not available'
                text = f'certificate verification failed ({number}{": " + detail if detail else ""})'
            tail = (_TRUST_CAVEAT if rule_id == 'TLS-CERT-UNTRUSTED' else '') + _FIRST_ERROR
            render = _Render(
                single=lambda text, url, label=label: (f"The scanner's standard TLS handshake was refused while fetching "
                                                       f"{sanitize_url(url)} (host '{label}'): {text}."),
                multi=lambda count, label=label: (f"The scanner's standard TLS handshake was refused for host '{label}' for "
                                                  f'{count} different reasons, each listed with the URLs it applies to.'),
                tail=tail)
            found.add(rule_id, key, url, (code if has_code else 10 ** 9, text), render, confidence)

    @staticmethod
    def _protocol_versions(found, pages):
        modern = {}                                   # endpoint key -> first modern connection per host
        for page in pages:
            response = page.response
            if getattr(response, 'scheme', None) != 'https':
                continue
            version = getattr(response, 'tls_version', None)
            if not isinstance(version, str):
                continue                                          # missing metadata: nothing is inferred from it
            endpoint = _endpoint(response.url)
            if endpoint is None:
                continue
            key, host, port, url = endpoint
            if version in OBSOLETE_VERSIONS:
                label = _label(host, port)
                render = _Render(
                    single=lambda text, url, label=label: f"The connection to '{label}' completed a handshake using {text}.",
                    multi=lambda count, label=label: (f"Connections to '{label}' completed handshakes using {count} different "
                                                      f'obsolete protocol versions, each listed with the URLs it applies to.'),
                    tail=' Each version is the one negotiated on the connection the scanner made.')
                found.add('TLS-PROTOCOL-OBSOLETE', key, url, (OBSOLETE_VERSIONS.index(version), f'{version} ({_OBSOLETE_NOTE[version]})'), render)
            elif version in MODERN_VERSIONS and key not in modern:
                modern[key] = (url, version, host, port)
        for key, (url, version, host, port) in modern.items():
            if ('TLS-PROTOCOL-OBSOLETE', key) in found.items:
                continue
            label = _label(host, port)
            render = _Render(
                single=lambda text, url, label=label: f"The connection to '{label}' negotiated {text}.",
                multi=lambda count: '',
                tail=(" The scanner's own TLS client does not offer TLS 1.0 or 1.1, so whether the server also accepts them was "
                      'not tested. This is not evidence that the server is secure.'))
            found.add('TLS-LEGACY-UNTESTED', key, url, (0, version), render, 'Informational')
