"""
Cookie security detector (passive).

It reads the Set-Cookie headers of responses the authorized crawler ALREADY collected
(context.pages). It sends no request of its own, never replays a cookie and never stores a cookie VALUE:
the parser discards the value as soon as it has split the header, so a value cannot reach a finding,
evidence text, `extra`, a repr, a log line or serialized output.

What is checked (RFC 6265bis semantics; where browsers differ the conservative reading is used):

  Secure        Missing on a cookie set over HTTPS. Over plain HTTP two things are kept apart, because they are
                different events:
                  * Transport: the Set-Cookie response header, value included, crosses the network in clear text,
                    so anyone who can observe that connection can read it. This is true whether or not the browser
                    later stores the cookie; rejecting a cookie does not un-send the header.
                  * Browser handling: whether the browser stores the cookie, and whether it later sends it in
                    requests. Browsers that follow RFC 6265bis refuse a Secure cookie from an insecure origin,
                    and refuse SameSite=None without Secure; a cookie without Secure that is otherwise valid is
                    stored and later sent over plain HTTP.
                Findings say which of these they mean: COOKIE-SENSITIVE-OVER-HTTP (session-like name, no Secure),
                COOKIE-SECURE-OVER-HTTP (Secure set, but the header travelled in clear text and the browser will
                not keep the cookie). http://localhost and loopback addresses are treated as trustworthy origins by
                browsers and are not flagged for using HTTP.

                Rejected cookies: where current browsers refuse to store a cookie (SameSite=None without Secure,
                a Secure cookie from an untrusted HTTP origin, an exact-case prefix violation) no finding claims
                that the browser stores or later sends it, and COOKIE-NO-SECURE is not added on top of the finding
                that explains the rejection. The header's exposure over plain HTTP is still reported, as a
                separate statement.
  HttpOnly      Missing. Never skipped. A cookie whose name suggests an anti-CSRF token is classified more
                carefully, because some designs (double-submit cookies) need script access and a passive
                scan cannot tell: the two conventional JavaScript-readable names (XSRF-TOKEN, csrftoken) are
                only an Informational observation, every other CSRF-named cookie is Potential.
  SameSite      Missing or unrecognised value (Strict, Lax and None are valid and not flagged on their own).
                SameSite=None without Secure is rejected by browsers; SameSite=None WITH Secure is only
                reported for session-like cookies, because it is legitimate for cross-site features.
  Prefixes      __Secure- needs Secure and a secure origin; __Host- additionally needs an explicit Path=/
                attribute and no Domain (draft-ietf-httpbis-cookie-prefixes). The exact spellings are reported
                as Confirmed. A different letter case (__host-) is only reported as Potential: the original
                prefix draft and some libraries match case-sensitively, while the current RFC 6265bis draft and
                recent Firefox versions match case-insensitively (Mozilla bug 1891349 / CVE-2024-5699), so whether
                such a cookie is enforced as a prefix cookie depends on the browser and version.
  Scope         A Domain attribute on a session-like cookie (shares it with every subdomain). Heuristic,
                reported as Potential. Path is not a security boundary, so it is not flagged.

Cookies that are being deleted (Max-Age<=0 or an Expires in the past) are skipped: they are not issued.

"Session-like" is decided from the cookie NAME only, on whole words (separators and camelCase are word
boundaries), never on substrings ("assessment", "obsession" and "authority" are not session-like). It is a
heuristic: it influences how likely an issue is rated (ordinary cookies are rated one likelihood step lower) and
is stated as such in the evidence; it never decides whether a missing attribute is reported and is never shown
as proof that a cookie holds a session.

Cookie names must be RFC 6265 tokens. A name with spaces, control characters, separators or non-ASCII characters
is not analyzed for attributes (what a browser would do with it varies); it is reported once as an Informational
COOKIE-MALFORMED-NAME observation instead of producing ordinary findings.

Identity: names are cut to MAX_PARSED_NAME characters before any regex runs. A longer name keeps a 128-bit
(32 hex characters) SHA-256 digest of the FULL name. A collision is possible in principle but its probability is
negligible: for n names the birthday bound is about n^2 / 2^129, i.e. below 10^-30 even for the 10^4 names a large
scan could see (a 32-bit digest, by contrast, could be collided by a hostile server in about 10^5 attempts). The
raw name is never shown.

Whitespace and case: like browsers, only space and horizontal tab are trimmed around names, attributes and values;
any other whitespace (no-break space, vertical tab, ...) is kept and therefore makes a name malformed or an
attribute unrecognized. Case folding is ASCII-only, so Unicode look-alikes (Kelvin sign, long s) never match.

Limits: only final responses are visible, so a cookie set on an intermediate redirect hop is not seen. A
nameless cookie ("Set-Cookie: abc") and a header containing CR, LF or NUL are ignored.
"""
import hashlib
import ipaddress
import re
import string
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import NamedTuple
from urllib.parse import urlsplit

from ..result_processor import redact
from ..rules import build_finding, get_rule
from ..rules.severity import lower
from ..sanitize import sanitize_url
from . import BaseDetector, register

MAX_COOKIES_PER_RESPONSE = 100
MAX_HEADER_CHARS = 8192            # browsers refuse far smaller cookies; this only bounds our own work
MAX_TRACKED = 500                  # distinct (rule, cookie name) pairs remembered
MAX_NAMES_PER_RULE = 25            # findings per rule (session-like cookies are listed first)
MAX_NAME_CHARS = 60
MAX_DIGEST_CHARS = 32            # hex characters of SHA-256 kept for names that were cut (128 bits)
MAX_LABEL_PREFIX = 20             # visible characters of a cut name in its label: 20 + '…#' + 32 hex <= MAX_NAME_CHARS
# Transport exposure of a Set-Cookie header delivered over plain HTTP. Independent of what the browser does with the cookie.
_HEADER_IN_CLEAR = ('The Set-Cookie response header, including the cookie value, was transmitted over plain HTTP, so anyone '
                    'able to observe that connection can read it, whether or not the browser stores the cookie.')

MAX_PARSED_NAME = 256              # longer names are cut before ANY regex runs: a hostile server must not make us spend CPU

_PREFIX = re.compile(r'^(__host-|__secure-)', re.I | re.A)      # ASCII case folding only
_ANTI_CSRF = re.compile(r'csrf|xsrf|requestverification|anti-?forgery', re.I | re.A)
# Whole-word session/authentication vocabulary. Words come from splitting on separators and camelCase, so
# "my_session" and "authToken" match but "obsession", "assessment", "authority" and "tokenizer" do not.
_SEGMENTS = re.compile(r'[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')
_SESSION_WORDS = frozenset({
    'session', 'sessions', 'sess', 'sid', 'sessid', 'sessionid', 'auth', 'authn', 'authz', 'authtoken', 'authorization',
    'oauth', 'token', 'jwt', 'login', 'logon', 'signin', 'remember', 'rememberme', 'credential', 'credentials',
    'password', 'passwd', 'pwd', 'secret', 'bearer', 'sso', 'apikey', 'phpsessid', 'jsessionid'})
# Classic ASP appends a random suffix (ASPSESSIONIDQQQSTRRT). This is the only prefix rule: suffix rules such as
# endswith('sessionid') also match "possessionid" and "obsessionid", so session ids are matched as exact words.
_SESSION_ID_PREFIXES = ('aspsessionid',)
# Names that frameworks conventionally keep readable by the application's own JavaScript (Angular/Laravel, Django).
_JS_READABLE_CSRF = frozenset({'xsrf-token', 'csrftoken'})
_SEPARATORS = frozenset('()<>@,;:\\"/[]?={}')
_DOMAIN_VALUE = re.compile(r'^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$')
_NAME_CHARS = re.compile(r"[^A-Za-z0-9!#$%&'*+.^_`|~-]")
_IDENTIFIER_RUN = re.compile(r'[A-Za-z0-9]{20,}')
_INT = re.compile(r'^-?[0-9]+$')


class Cookie(NamedTuple):
    """A parsed Set-Cookie header WITHOUT its value."""
    name: str
    secure: bool
    httponly: bool
    samesite: object            # None (absent) | 'strict' | 'lax' | 'none' | 'invalid'
    domain: object              # lower-case host without the leading dot, or None
    path: object               # a valid Path attribute (starts with '/'), or None
    conflicts: tuple            # attribute names repeated with different values
    deleted: bool               # Max-Age<=0 or Expires in the past
    name_problems: tuple        # why the name is not an RFC 6265 token (empty tuple = valid)
    name_digest: object         # MAX_DIGEST_CHARS hex chars of SHA-256 over the FULL name when it was cut, else None


# ---------------------------------------------------------------- parsing
def _is_deleted(max_age, expires, now):
    if max_age is not None:                         # Max-Age wins over Expires
        return max_age <= 0
    if expires is not None:
        return expires <= now
    return False


def _parse_expires(text):
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _lower(text):
    """ASCII-only lower-casing. str.lower() folds Unicode look-alikes (the Kelvin sign becomes 'k'), which would
    make names and attributes match that a browser does not match."""
    return text.translate(_ASCII_LOWER)


def _parse_max_age(value):
    """
    Max-Age as an int clamped to +/-10**18, or None when it is not an integer. Never raises: int() refuses more
    than 4300 digits, and a hostile or buggy server must not be able to make us drop the whole cookie.
    """
    if not _INT.fullmatch(value):
        return None
    negative = value.startswith('-')
    digits = value.lstrip('-').lstrip('0')
    if len(digits) > 18:
        return -10 ** 18 if negative else 10 ** 18
    number = int(digits or '0')
    return -number if negative else number


def _name_problems(name):
    """Reasons a cookie name is not an RFC 6265 token (empty tuple if it is valid). Linear; bounded loop."""
    if not _NAME_CHARS.search(name):
        return ()
    problems = set()
    for ch in name[:MAX_PARSED_NAME]:
        code = ord(ch)
        if code < 0x20 or code == 0x7f:
            problems.add('control characters')
        elif ch == ' ':
            problems.add('spaces')
        elif code > 0x7e:
            problems.add('non-ASCII characters')
        elif ch in _SEPARATORS:
            problems.add('separator characters')
    return tuple(sorted(problems)) or ('invalid characters',)


def parse_set_cookie(header, now=None):
    """Parse one Set-Cookie header line. Returns a Cookie (value dropped) or None if it cannot be a cookie."""
    if not isinstance(header, str) or len(header) > MAX_HEADER_CHARS or re.search(r'[\x00\r\n]', header):
        return None
    first, *attributes = header.split(';')
    if '=' not in first:
        return None                                  # nameless cookie: nothing to identify
    full_name = first.split('=', 1)[0].strip(' \t')   # the value (everything after '=') is deliberately dropped
    if not full_name:
        return None
    problems = _name_problems(full_name)
    digest = (hashlib.sha256(full_name.encode('utf-8', 'replace')).hexdigest()[:MAX_DIGEST_CHARS]
              if len(full_name) > MAX_PARSED_NAME else None)
    name = full_name[:MAX_PARSED_NAME]
    secure = httponly = False
    samesite, domain, path = [], None, None
    max_age = expires = None
    seen = {'domain': set(), 'path': set()}
    for raw in attributes:
        attr = raw.strip(' \t')
        if not attr:
            continue
        key, _sep, value = attr.partition('=')
        key, value = _lower(key.strip(' \t')), value.strip(' \t')
        if key == 'secure':
            secure = True                            # a flag: its presence counts, a value is ignored
        elif key == 'httponly':
            httponly = True
        elif key == 'samesite':
            samesite.append(_lower(value) if _lower(value) in ('strict', 'lax', 'none') else 'invalid')
        elif key == 'domain':
            cleaned = _lower(value.lstrip('.'))
            if cleaned:                              # an empty Domain is ignored by browsers
                domain = cleaned
                seen['domain'].add(cleaned)
        elif key == 'path':
            if value.startswith('/'):
                path = value
                seen['path'].add(value)
            else:
                path = None                          # invalid/empty: the default path applies, overriding any earlier Path
        elif key == 'max-age':
            parsed = _parse_max_age(value)
            if parsed is not None:                   # an unusable Max-Age is ignored; the cookie is still analyzed
                max_age = parsed
        elif key == 'expires':
            expires = _parse_expires(value) or expires
    conflicts = tuple(sorted(
        [k for k, vals in seen.items() if len(vals) > 1] + (['samesite'] if len(set(samesite)) > 1 else [])))
    now = now or datetime.now(timezone.utc)
    return Cookie(name=name, secure=secure, httponly=httponly, samesite=samesite[-1] if samesite else None,
                  domain=domain, path=path, conflicts=conflicts, deleted=_is_deleted(max_age, expires, now),
                  name_problems=problems, name_digest=digest)


# ---------------------------------------------------------------- classification helpers
def is_anti_csrf(name):
    return bool(_ANTI_CSRF.search(name))


def is_session_like(name):
    """Heuristic on whole words of the cookie name only (see module docstring); never proof of a session."""
    bare = _PREFIX.sub('', name)[:MAX_PARSED_NAME]
    if is_anti_csrf(bare):
        return False
    parts = [_lower(p) for p in _SEGMENTS.split(bare) if p]
    words = parts + [a + b for a, b in zip(parts, parts[1:])]          # "api" + "key" -> "apikey"
    for word in words:
        for form in {word, word.rstrip('0123456789')}:                  # "sessionid2", "sid1"
            if form in _SESSION_WORDS or form.startswith(_SESSION_ID_PREFIXES):
                return True
    return False


def csrf_kind(name):
    """None (not CSRF-named), 'conventional' (a name frameworks keep script-readable) or 'generic'."""
    bare = _PREFIX.sub('', name)[:MAX_PARSED_NAME]
    if not is_anti_csrf(bare):
        return None
    return 'conventional' if _lower(bare) in _JS_READABLE_CSRF else 'generic'


def prefix_kind(name):
    """'__host-' / '__secure-' (lower-case) if the name starts with a prefix in ANY letter case, else None."""
    match = _PREFIX.match(name)
    return _lower(match.group(1)) if match else None


def prefix_is_exact(name):
    """True for the canonical spellings '__Host-' and '__Secure-'."""
    return name.startswith(('__Host-', '__Secure-'))


def is_trustworthy_host(host):
    """localhost and loopback addresses: browsers treat http:// to them as a secure context."""
    host = (host or '').lower().strip('[]').rstrip('.')
    if host == 'localhost' or host.endswith('.localhost'):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def display_name(name):
    """Cookie name as shown to users: printable, bounded, and with long identifier-like runs masked."""
    text = _NAME_CHARS.sub('?', name)
    text = _IDENTIFIER_RUN.sub(lambda m: '[id]' if re.search(r'[0-9]', m.group(0)) else m.group(0), text)
    text = redact(text)
    return text if len(text) <= MAX_NAME_CHARS else text[:MAX_NAME_CHARS - 1] + '…'


def cookie_label(cookie):
    """
    The cookie's name as shown to users AND the aggregation key. Long names (cut at parse time) carry the digest of
    the full name, so two distinct long names are kept apart (a collision has negligible, not zero, probability).
    Shorter names merge only through the documented identifier masking ("sess_[id]"), which is what makes per-user
    session cookie names one finding.
    """
    if cookie.name_digest:
        return f'{display_name(cookie.name[:MAX_LABEL_PREFIX])}…#{cookie.name_digest}'
    return display_name(cookie.name)


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip('[]'))
        return True
    except ValueError:
        return False


def _scheme(response):
    return (urlsplit(response.url).scheme or getattr(response, 'scheme', '') or '').lower()


# ---------------------------------------------------------------- aggregation
class _Collector:
    """
    One finding per (rule, cookie name), listing every page that set the cookie that way. The names
    listed per rule are bounded (session-like cookies first) and the rest is counted, never silently dropped.
    """

    def __init__(self):
        self.items = {}
        self.dropped = {}

    def add(self, rule_id, name, url, evidence, confidence='Confirmed', likelihood=None, sensitive=False):
        key = (rule_id, name)
        entry = self.items.get(key)
        if entry is None:
            if len(self.items) >= MAX_TRACKED:
                self.dropped[rule_id] = self.dropped.get(rule_id, 0) + 1
                return
            entry = self.items[key] = {'urls': [], 'evidence': evidence, 'confidence': confidence, 'seq': len(self.items),
                                       'likelihood': likelihood, 'sensitive': sensitive}
        if confidence == 'Confirmed':
            entry['confidence'] = 'Confirmed'
        if url not in entry['urls']:
            entry['urls'].append(url)

    def findings(self):
        by_rule = {}
        for (rule_id, name), e in self.items.items():
            by_rule.setdefault(rule_id, []).append((name, e))
        out = []
        for rule_id, entries in by_rule.items():
            entries.sort(key=lambda item: (not item[1]['sensitive'], item[1]['seq']))
            shown = entries[:MAX_NAMES_PER_RULE]
            omitted = len(entries) - len(shown) + self.dropped.get(rule_id, 0)
            for name, e in shown:
                evidence = e['evidence']
                if len(e['urls']) > 1:
                    evidence += f' {len(e["urls"])} pages set the cookie this way.'
                if omitted:
                    evidence += f' {omitted} more cookie name(s) have the same issue and are not listed.'
                out.append(build_finding(
                    rule_id, e['urls'], evidence, confidence=e['confidence'], instance=name, subject=name,
                    likelihood=e['likelihood'],
                    extra={'cookie_name': name, 'session_like_name': e['sensitive']}))
        return out


# ---------------------------------------------------------------- detector
@register
class CookieSecurityDetector(BaseDetector):
    category = 'cookie_security'
    name = 'cookie-security'

    def run(self, context):
        # Error handling is deliberately narrow. Everything an origin server can send is handled as DATA, not as an
        # exception: HttpResponse.header_all() only filters a list of (str, str) pairs produced by the HTTP layer, and
        # parse_set_cookie() is total (a header it cannot use yields None or a cookie flagged COOKIE-MALFORMED-NAME,
        # never an exception; see the fuzz and hostile-input tests). One unusable cookie is therefore skipped
        # without any try/except, and the others are still analyzed. An exception that does escape from here or from
        # _check() is a programming error and must not be hidden: ScanEngine records it ("cookie-security: failed
        # (<ExceptionClass>)", status completed_with_errors), so an incomplete result is never presented as complete.
        found = _Collector()
        for page in context.pages:
            response = page.response
            for header in response.header_all('set-cookie')[:MAX_COOKIES_PER_RESPONSE]:
                cookie = parse_set_cookie(header)
                if cookie is not None and not cookie.deleted:
                    self._check(found, response, cookie)
        return found.findings()

    # -- checks ------------------------------------------------------------
    def _check(self, found, r, c):
        name = cookie_label(c)
        session_like = is_session_like(c.name)
        https = _scheme(r) == 'https'
        trusted = is_trustworthy_host(urlsplit(r.url).hostname)
        where = f'{r.method} {sanitize_url(r.url)}'
        subject = f"The cookie '{name}' set in the response to {where}"
        tail = ' The cookie value is not recorded.'
        note = (f' The header repeats {", ".join(c.conflicts)} with different values; the last one applies in '
                f'browsers that follow the specification.' if c.conflicts else '')

        def add(rule_id, evidence, confidence='Confirmed', ordinary_lower=False):
            likelihood = lower(get_rule(rule_id).likelihood) if ordinary_lower and not session_like else None
            basis = ''
            if ordinary_lower and confidence == 'Confirmed':      # say how the name heuristic shaped the rating
                basis = (' The rating treats the cookie as session-like because of its name (a name-based heuristic, '
                         'not proof).' if session_like else
                         ' The rating is lower because the name does not look like a session or authentication '
                         'cookie (a name-based heuristic; the cookie may still matter).')
            found.add(rule_id, name, r.url, evidence + basis + note + tail, confidence, likelihood, session_like)

        if c.name_problems:                    # not an RFC 6265 token: classify, do not analyze attributes
            found.add('COOKIE-MALFORMED-NAME', name, r.url,
                      f'{subject} has a name that is not a valid cookie token (it contains '
                      f'{", ".join(c.name_problems)}), so its attributes were not analyzed.' + tail,
                      'Informational', None, False)
            return

        problems = self._prefix_problems(c, r, https, trusted)
        # Would a current browser refuse to store this cookie? Then it is neither "sent over HTTP" nor "exposed";
        # the finding that explains the rejection is reported instead of a second, contradictory one.
        exact_prefix_violation = bool(problems) and prefix_is_exact(c.name)
        none_without_secure = c.samesite == 'none' and not c.secure
        over_untrusted_http = not https and not trusted
        secure_from_untrusted_http = c.secure and over_untrusted_http
        rejected = exact_prefix_violation or none_without_secure or secure_from_untrusted_http
        if problems and prefix_is_exact(c.name):
            kind = c.name[:len('__Host-') if prefix_kind(c.name) == '__host-' else len('__Secure-')]
            add('COOKIE-PREFIX-INVALID',
                f'{subject} uses the {kind} prefix but {"; ".join(problems)}. Browsers that implement cookie '
                f'prefixes reject such a cookie.' + (f' {_HEADER_IN_CLEAR}' if over_untrusted_http else ''))
        elif problems:                                   # e.g. '__host-': browser behaviour is not assumed
            kind = c.name[:len('__host-') if prefix_kind(c.name) == '__host-' else len('__secure-')]
            add('COOKIE-PREFIX-INVALID',
                f'{subject} starts with {kind} in a different letter case than the canonical prefix. Browsers that '
                f'match prefixes case-insensitively would treat it as a prefix cookie, but it {"; ".join(problems)}. '
                f'Matching rules differ between browsers and versions (older specification text is case-sensitive, the '
                f'current draft is case-insensitive), so whether the cookie is enforced as a prefix cookie varies, and '
                f'a server that treats the name case-insensitively may assume protection the cookie does not have.',
                confidence='Potential')

        if https and not c.secure and not rejected:
            add('COOKIE-NO-SECURE', f'{subject} (HTTPS) has no Secure attribute, so browsers also send it over plain '
                                    f'HTTP.', ordinary_lower=True)
        if over_untrusted_http and session_like and not c.secure:
            if exact_prefix_violation or none_without_secure:       # the browser will probably refuse to store it
                why = 'an invalid prefix' if exact_prefix_violation else 'SameSite=None without Secure'
                storage = (f'Browsers that enforce the rules for {why} reject the cookie (reported separately), so '
                           f'whether it is stored and later sent depends on the browser.')
            else:
                storage = ('It has no Secure attribute, so browsers accept it and send it in clear text on later '
                           'requests over plain HTTP.')
            add('COOKIE-SENSITIVE-OVER-HTTP',
                f'{subject} is set over plain HTTP and its name suggests a session or authentication cookie (a '
                f'name-based heuristic). {_HEADER_IN_CLEAR} {storage}', confidence='Potential')
        if secure_from_untrusted_http and not exact_prefix_violation:    # an exact prefix violation reports this itself
            add('COOKIE-SECURE-OVER-HTTP',
                f'{subject} sets the Secure attribute but was delivered over plain HTTP. {_HEADER_IN_CLEAR} '
                f'Separately, browsers that follow RFC 6265bis refuse to store a Secure cookie from an insecure '
                f'origin (http://localhost and other trustworthy origins excepted), so the browser will not keep it '
                f'or send it in later requests; that rejection does not protect the header that was already sent.',
                ordinary_lower=True)

        if not c.httponly:
            kind = csrf_kind(c.name)
            if kind == 'conventional':
                add('COOKIE-NO-HTTPONLY',
                    f'{subject} has no HttpOnly attribute. Its name follows a convention (XSRF-TOKEN, csrftoken) where '
                    f'frameworks deliberately keep the anti-CSRF cookie readable by the application\'s own JavaScript, '
                    f'so this is an observation rather than a weakness by itself.', confidence='Informational')
            elif kind == 'generic':
                add('COOKIE-NO-HTTPONLY',
                    f'{subject} has no HttpOnly attribute, so script running in the page can read it. Its name '
                    f'suggests an anti-CSRF cookie: some designs (double-submit cookies) need script access, others '
                    f'do not, and a passive scan cannot tell which applies here.', confidence='Potential',
                    ordinary_lower=True)
            else:
                add('COOKIE-NO-HTTPONLY', f'{subject} has no HttpOnly attribute, so script running in the page can '
                                          f'read it.', ordinary_lower=True)

        if c.samesite is None:
            add('COOKIE-SAMESITE-MISSING', f'{subject} sets no SameSite attribute, so it relies on browser '
                                           f'defaults.', ordinary_lower=True)
        elif c.samesite == 'invalid':
            add('COOKIE-SAMESITE-MISSING', f'{subject} sets a SameSite attribute with an unrecognized value; '
                                           f'browsers treat it as unspecified.', ordinary_lower=True)
        elif c.samesite == 'none':
            if not c.secure:
                add('COOKIE-SAMESITE-NONE-INSECURE',
                    f'{subject} sets SameSite=None without Secure. Browsers that follow the SameSite specification '
                    f'reject such a cookie, so it is not stored; older browsers that accept it send it on cross-site '
                    f'requests, including over plain HTTP.' +
                    (f' Separately from that, {_HEADER_IN_CLEAR[0].lower() + _HEADER_IN_CLEAR[1:]}'
                     if over_untrusted_http else ''))
            elif session_like:
                add('COOKIE-SAMESITE-NONE', f'{subject} sets SameSite=None, and its name suggests a session or '
                                            f'authentication cookie (a name-based heuristic).',
                    confidence='Potential')

        self._check_scope(add, subject, c, r, session_like)

    @staticmethod
    def _prefix_problems(c, r, https, trusted):
        kind = prefix_kind(c.name)
        if not kind:
            return []
        problems = []
        if not c.secure:
            problems.append('does not set Secure')
        if not https and not trusted:
            problems.append('was set over plain HTTP, but the prefix requires a secure origin')
        if kind == '__host-':
            if c.domain:
                problems.append('sets a Domain attribute')
            if c.path is None:
                problems.append('has no valid Path attribute (the prefix requires Path=/)')
            elif c.path != '/':
                problems.append('sets a Path other than /')
        return problems

    @staticmethod
    def _check_scope(add, subject, c, r, session_like):
        # An exact-case __Host- cookie with Domain is rejected by every browser that implements prefixes (case
        # sensitive or not), and COOKIE-PREFIX-INVALID already reports it. A case variant (__host-) is enforced only
        # by some browsers, so its Domain scope is still analyzed like any other cookie's.
        if not (c.domain and session_like) or (prefix_kind(c.name) == '__host-' and prefix_is_exact(c.name)):
            return
        host = (urlsplit(r.url).hostname or '').lower()
        if not host or _is_ip(host) or not _DOMAIN_VALUE.match(c.domain):
            return
        if host != c.domain and not host.endswith('.' + c.domain):
            return                                        # not a domain match: browsers reject the cookie
        add('COOKIE-BROAD-DOMAIN',
            f'{subject} sets Domain={c.domain}, which makes it available to every subdomain of {c.domain}, and its '
            f'name suggests a session or authentication cookie (a name-based heuristic).', confidence='Potential')
