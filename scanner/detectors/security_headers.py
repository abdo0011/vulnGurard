"""
Security Headers detector (passive).

Works only on responses the authorized crawler already fetched: it makes NO requests of its own.
A header is reported only when it is missing where it matters or its value is clearly weak;
the mere presence of a header is never a finding.

Which responses are judged
  * Strict-Transport-Security ..... every HTTPS response, whatever its Content-Type (browsers
                                    process the header on any secure response and ignore it over
                                    HTTP). A missing header is reported from 2xx responses only; a
                                    present-but-weak/invalid header is reported from ANY status,
                                    because e.g. max-age=0 on a redirect still switches HSTS off.
  * X-Content-Type-Options ........ every 2xx response
  * all other headers ............. 2xx HTML documents only (redirects, errors and non-HTML
                                    responses are not documents a browser applies these to)

Content-Security-Policy
  * absent / valid / present-but-malformed are three different states. A header whose policies
    contain no recognised directive is reported as HDR-CSP-MALFORMED, never as "not sent".
  * header vs <meta>: a meta policy counts as a CSP and its script rules are judged like a header's,
    but is reported separately (HDR-CSP-META-ONLY): browsers ignore frame-ancestors, report-uri and
    sandbox in a meta tag, Report-Only is not valid there, and it only governs content parsed AFTER
    the tag. It is "early" only if nothing that loads/executes, no body content and no non-blank
    text precedes it (whitespace, comments and <title> text do not count); otherwise it is "late",
    is NOT counted as page protection and is reported as HDR-CSP-META-LATE. Placement uses a real
    HTML parser (comments, script text, <noscript>/<template> are ignored). Limitation: static
    source-order analysis only; scripts that insert tags later are not modelled, and if markup is so
    broken that parsing aborts, later tags are not seen (reported as missing = conservative).
  * frame-ancestors (header CSP only). ABSENT and EMPTY are different: an absent directive restricts nothing
    (X-Frame-Options is then consulted), whereas a present directive is enforced, browsers ignore
    X-Frame-Options, and its effective source list (valid expressions only; 'none' and invalid tokens are
    dropped) decides the outcome. An empty effective list ('none', an empty directive, or only invalid
    tokens) matches no ancestor and blocks framing, so it is restrictive. '*' or a bare scheme source
    ('https:') is permissive and is reported as HDR-FRAME-ANCESTORS-WEAK.
  * 'unsafe-inline' is neutralised in every browser generation only by a valid nonce or hash.
    'strict-dynamic' alone is NOT enough: only CSP3 browsers honour it, older ones still allow inline
    scripts. Such a policy is reported with confidence Potential; an 'unsafe-inline' without
    strict-dynamic is Confirmed.

HSTS syntax follows the Chromium parser (which implements RFC 6797): directive names are
case-insensitive; max-age needs ASCII digits, optionally inside DOUBLE quotes (single quotes are
not quoting); a duplicate directive, a missing max-age or a valued includeSubDomains makes browsers
reject the whole header. Whitespace around "=" is tolerated (browser behaviour is not specified).

Permissions-Policy: the deprecated Feature-Policy header does NOT satisfy the check. It was
superseded, uses a different syntax and is not consistently supported; its presence is mentioned in
the evidence only.

Findings are collected per rule across all pages, so a site-wide gap yields ONE finding that lists
every affected URL (the original, unmasked URLs stay internal; evidence and serialization show
sanitized ones) instead of one per page.
"""
import re
from html.parser import HTMLParser
from typing import NamedTuple

from ..rules import build_finding
from ..sanitize import sanitize_url
from . import BaseDetector, register

HTML_TYPES = ('text/html', 'application/xhtml+xml')
HSTS_MIN_SECONDS = 15552000                 # 180 days (Mozilla's minimum recommendation is 6 months)
REFERRER_VALUES = {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
                   'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}
_SCHEME_SOURCES = ('https:', 'http:', 'data:')
_MAX_BODY_SCAN = 200_000                    # characters searched for <meta> tags
META_UNSUPPORTED_DIRECTIVES = ('frame-ancestors', 'report-uri', 'sandbox')      # ignored by browsers in <meta>
# A policy is only a policy if at least one of its directives is one a browser knows.
RECOGNIZED_DIRECTIVES = frozenset('''
    default-src script-src script-src-elem script-src-attr style-src style-src-elem style-src-attr img-src
    connect-src font-src object-src media-src frame-src child-src worker-src manifest-src prefetch-src
    base-uri form-action frame-ancestors sandbox report-uri report-to upgrade-insecure-requests
    block-all-mixed-content require-trusted-types-for trusted-types plugin-types navigate-to'''.split())
# Elements that may appear in <head> without starting the body.
_HEAD_TAGS = {'html', 'head', 'meta', 'title', 'base', 'link', 'style', 'script', 'noscript', 'template'}
# Elements that load a resource or run code, so content/behaviour may exist BEFORE a later meta CSP.
_LOADING_TAGS = {'script', 'style', 'img', 'iframe', 'frame', 'object', 'embed', 'video', 'audio', 'source',
                 'track', 'picture'}
_LOADING_LINK_RELS = {'stylesheet', 'preload', 'modulepreload', 'prefetch', 'prerender', 'icon',
                      'apple-touch-icon', 'shortcut', 'manifest'}
_HTML_WHITESPACE = ' \t\n\r\f﻿'        # ASCII whitespace + BOM; NOT \xa0 (a no-break space is content)

_NONCE = re.compile(r"'nonce-[^']*'", re.I)
# nonce-source / hash-source: 'nonce-' / 'sha256-' / 'sha384-' / 'sha512-' + base64 or base64url value.
# (Tokens are lower-cased by parse_csp, so only the lower-case alphabet is listed.)
_NONCE_OR_HASH = re.compile(r"^'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_-]+={0,2}'$")
_SCHEME_SOURCE = re.compile(r'^[a-z][a-z0-9+.-]*:$')
_HOST_SOURCE = re.compile(
    r'^(?:[a-z][a-z0-9+.-]*://)?(?:\*\.)?(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::(?:[0-9]{1,5}|\*))?(?:/[^\s;,]*)?$|^\*$')
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DIGITS = re.compile(r'[0-9]+', re.ASCII)


# ---------------------------------------------------------------- CSP parsing
def parse_csp(header_values):
    """
    Parse Content-Security-Policy header values into a list of policies, each a dict
    {directive: [tokens]} (the first occurrence of a directive wins, as in browsers). A header may
    carry several comma-separated policies; malformed pieces are skipped rather than raising.
    """
    policies = []
    for value in header_values:
        for raw_policy in (value or '').split(','):
            directives = {}
            for part in raw_policy.split(';'):
                tokens = part.split()
                if tokens:
                    directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
            if directives:
                policies.append(directives)
    return policies


def has_recognized_directive(policy):
    """A policy with no directive a browser knows has no effect: it is malformed, not 'a policy'."""
    return any(name in RECOGNIZED_DIRECTIVES for name in policy)


def usable_policies(header_values):
    return [p for p in parse_csp(header_values) if has_recognized_directive(p)]


class MetaInfo(NamedTuple):
    raws: list          # content attributes of every CSP meta tag (for evidence)
    early: list         # usable policies of meta tags placed before any content (full coverage)
    late: list          # usable policies of meta tags placed after content (partial coverage)
    ignored: list       # directives present in meta CSPs that browsers ignore there (sorted)
    blocker: str        # what preceded the first late tag, e.g. '<script>'; '' when none
    referrer: bool      # a <meta name="referrer"> exists
    unusable: bool      # a CSP meta tag exists but yielded no usable policy


class _MetaScanner(HTMLParser):
    """Collects CSP/referrer meta tags together with whether content precedes them."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.csp = []                       # (content, early, blocker)
        self.referrer = False
        self._blocker = ''                  # first thing that makes later meta tags "late"
        self._skip = 0                      # depth inside <noscript>/<template>: not an active document
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {}
        for key, value in attrs:
            a.setdefault((key or '').lower(), value or '')
        if tag in ('noscript', 'template'):
            self._skip += 1
            return
        if self._skip:
            return
        if tag == 'title':
            self._in_title = True
        if tag == 'meta':
            if a.get('http-equiv', '').strip().lower() == 'content-security-policy':
                self.csp.append((a.get('content', ''), not self._blocker, self._blocker))
            elif a.get('name', '').strip().lower() == 'referrer':
                self.referrer = True
            return
        if self._blocker:
            return
        if tag == 'link':
            rels = set(a.get('rel', '').lower().split())
            if rels & _LOADING_LINK_RELS:
                self._blocker = '<link rel="%s">' % a.get('rel', '').strip()[:30]
        elif tag in _LOADING_TAGS:
            self._blocker = f'<{tag}>'
        elif tag not in _HEAD_TAGS:
            self._blocker = ('the start of <body>' if tag == 'body' else f'page content (<{tag}>)')

    def handle_endtag(self, tag):
        if tag in ('noscript', 'template') and self._skip:
            self._skip -= 1
        elif tag == 'title':
            self._in_title = False

    def handle_data(self, data):
        # Non-blank text is page content, so a meta tag after it protects only what follows.
        # Whitespace, comments, doctype and <title> text are not content.
        if self._skip or self._in_title or self._blocker:
            return
        if data.strip(_HTML_WHITESPACE):
            self._blocker = 'text content'


def scan_meta(body):
    """
    Meta CSP / meta referrer information for one HTML document (see the module docstring).
    Never raises: on malformed markup it returns what was seen before parsing stopped.
    Report-Only is not valid in a meta tag and is never matched.
    """
    scanner = _MetaScanner()
    try:
        scanner.feed(body or '')
        scanner.close()
    except Exception:
        pass
    raws, early, late, ignored, blocker = [], [], [], set(), ''
    for content, is_early, why in scanner.csp:
        raws.append(content)
        for policy in parse_csp([content]):
            for name in META_UNSUPPORTED_DIRECTIVES:
                if policy.pop(name, None) is not None:
                    ignored.add(name)
            if has_recognized_directive(policy):
                (early if is_early else late).append(policy)
        if not is_early and not blocker:
            blocker = why
    return MetaInfo(raws, early, late, sorted(ignored), blocker, scanner.referrer,
                    bool(scanner.csp) and not (early or late))


# ---------------------------------------------------------------- CSP semantics
def _script_weaknesses(policy):
    """
    [(reason, certain)] for one policy's script scope; [] when fine or when it has no script scope.
    `certain` is False when the weakness only exists for browsers without CSP3 'strict-dynamic' support.
    """
    tokens = policy.get('script-src', policy.get('default-src'))
    if tokens is None:
        return []                           # e.g. a policy that only sets frame-ancestors: not weak
    strict_dynamic = "'strict-dynamic'" in tokens
    has_nonce_or_hash = any(_NONCE_OR_HASH.match(t) for t in tokens)
    out = []
    # Only a valid nonce/hash makes EVERY CSP2+ browser ignore 'unsafe-inline'. 'strict-dynamic' alone
    # does so only in CSP3 browsers; older ones still allow inline scripts.
    if "'unsafe-inline'" in tokens and not has_nonce_or_hash:
        if strict_dynamic:
            out.append(("'unsafe-inline' without a nonce or hash ('strict-dynamic' disables it only in CSP3 "
                        "browsers; older browsers still allow inline scripts)", False))
        else:
            out.append(("'unsafe-inline' without a nonce or hash", True))
    if "'unsafe-eval'" in tokens:
        out.append(("'unsafe-eval'", True))
    # Host and scheme sources are ignored by CSP3 browsers only when 'strict-dynamic' is paired with a
    # nonce/hash (the documented backwards-compatible pattern); otherwise they keep their effect.
    if not (strict_dynamic and has_nonce_or_hash):
        certain = not strict_dynamic
        if '*' in tokens:
            out.append(('wildcard source (*)', certain))
        for scheme in _SCHEME_SOURCES:
            if scheme in tokens:
                out.append((f'scheme source ({scheme})', certain))
    return out


def csp_script_weaknesses(policy):
    """Reasons this single policy fails to restrict scripts; [] when it is fine or has no script scope."""
    return [reason for reason, _certain in _script_weaknesses(policy)]


def classify_frame_ancestors(tokens):
    """
    Classify ONE present, enforced frame-ancestors directive by its EFFECTIVE source list: the valid source
    expressions it contains. 'none' and invalid tokens are not sources and are dropped, as browsers ignore them.

    'restrictive' - the effective list names only some origins, or NONE at all. An EMPTY effective list
                    ('none', an empty directive, or only invalid tokens) matches no ancestor, so framing is
                    blocked (CSP source-list matching returns "Does Not Match" for an empty list; Chromium's
                    own representation of 'none' is exactly an empty list).
    'permissive'  - the effective list contains '*' or a bare scheme source such as https:, which lets
                    (nearly) any site frame the page.

    Callers must only pass a directive that is PRESENT. A directive that is absent from the policy is not an
    empty directive: it imposes no restriction at all.
    """
    effective = [t for t in tokens if t == "'self'" or _SCHEME_SOURCE.match(t) or _HOST_SOURCE.match(t)]
    if any(t == '*' or _SCHEME_SOURCE.match(t) for t in effective):
        return 'permissive'
    return 'restrictive'


# ---------------------------------------------------------------- other header parsing
def parse_hsts_max_age(value):
    """
    max-age in seconds, or None when the header is not valid HSTS (browsers then ignore it):
    no max-age, a duplicate directive, a non-numeric/negative/single-quoted max-age, or a valued
    includeSubDomains. A double-quoted value is valid (RFC 6797 directive-value = token / quoted-string).
    """
    seen, max_age = set(), None
    for part in (value or '').split(';'):
        part = part.strip()
        if not part:
            continue
        name, sep, val = part.partition('=')
        name, val = name.strip().lower(), val.strip()
        if not _TOKEN.match(name) or name in seen:
            return None
        seen.add(name)
        if name == 'max-age':
            if not sep:
                return None
            if val.startswith('"'):
                if len(val) < 2 or not val.endswith('"'):
                    return None
                val = re.sub(r'\\(.)', r'\1', val[1:-1])        # unescape quoted-pair
            if not _DIGITS.fullmatch(val):                      # ASCII digits only ("²" and "١٢" are not)
                return None
            max_age = int(val)
        elif name == 'includesubdomains' and sep:
            return None
    return max_age


def effective_referrer_policy(value):
    """Browsers use the LAST token they recognise in a comma-separated list."""
    effective = None
    for token in (value or '').split(','):
        token = token.strip().lower()
        if token in REFERRER_VALUES:
            effective = token
    return effective


_URL_QUERY = re.compile(r'\?[^\s;,\']*')


def _safe(value, limit=200):
    """
    Header value as evidence. Nonces are per-response secrets, and URLs inside policies (e.g.
    report-uri) sometimes carry tokens in their query string, so both are masked here, in addition
    to the generic redaction the result processor applies later.
    """
    text = _NONCE.sub("'nonce-[redacted]'", (value or '').strip())
    return _URL_QUERY.sub('?[query redacted]', text)[:limit]


def _u(url):
    """URL for evidence text: query values, fragment and credentials are masked (see scanner/sanitize.py)."""
    return sanitize_url(url)


def _header_names(response):
    names = sorted({k.lower() for k, _v in response.headers})
    return ', '.join(names[:25]) + (', ...' if len(names) > 25 else '') or '(none)'


def _is_success(response):
    return 200 <= response.status < 300


def _is_document(response):
    return _is_success(response) and response.content_type in HTML_TYPES


class _Collector:
    """
    Groups results per rule so a site-wide gap becomes one finding with many URLs.

    Pages that fail a rule in DIFFERENT ways (e.g. HSTS max-age=10 on one page, max-age=0 on another)
    pass a `variant` and a `weight` (higher = more important; any mutually comparable value, such as
    a tuple, per rule). The evidence shown is the MAX_VARIANTS most important variants, worst first
    (ties keep page order), NOT the first ones seen, so a serious configuration on a later page can
    never be hidden behind earlier, milder ones. Distinct variants that do not fit are counted.
    The finding is Confirmed if any page is confirmed, otherwise Potential.
    """
    MAX_VARIANTS = 3
    MAX_TRACKED = 200               # distinct variants remembered per rule (bounds memory on huge sites)

    def __init__(self):
        self.items = {}

    def add(self, rule_id, url, evidence, variant=None, weight=0, confidence='Confirmed'):
        entry = self.items.setdefault(rule_id, {'urls': [], 'variants': {}, 'dropped': 0, 'seq': 0,
                                                'confidence': confidence})
        if confidence == 'Confirmed':
            entry['confidence'] = 'Confirmed'
        if url not in entry['urls']:
            entry['urls'].append(url)
        if variant in entry['variants']:
            return
        entry['seq'] += 1
        new = (weight, entry['seq'], evidence)
        if len(entry['variants']) >= self.MAX_TRACKED:
            # Table full: keep the MOST important variants, so a serious one seen late still gets in.
            worst_key = min(entry['variants'], key=lambda k: (entry['variants'][k][0], -entry['variants'][k][1]))
            worst = entry['variants'][worst_key]
            entry['dropped'] += 1
            if (new[0], -new[1]) <= (worst[0], -worst[1]):
                return                                  # not more important than anything already kept
            del entry['variants'][worst_key]
        entry['variants'][variant] = new

    def findings(self):
        out = []
        for rule_id, e in self.items.items():
            ranked = sorted(e['variants'].values(), key=lambda v: (v[0], -v[1]), reverse=True)
            shown = ranked[:self.MAX_VARIANTS]
            evidence = ' '.join(v[2] for v in shown)
            omitted = len(ranked) - len(shown) + e['dropped']
            if omitted:
                evidence += f' {omitted} other distinct configuration(s) on these pages are not shown.'
            if len(e['urls']) > 1:
                evidence += f' {len(e["urls"])} pages are affected in total.'
            out.append(build_finding(rule_id, e['urls'], evidence, confidence=e['confidence']))
        return out


@register
class SecurityHeadersDetector(BaseDetector):
    category = 'security_headers'
    name = 'security-headers'

    def run(self, context):
        found = _Collector()
        for page in context.pages:
            response = page.response
            self._guarded(self._check_hsts, found, response)                 # any HTTPS response
            if _is_success(response):
                self._guarded(self._check_content_type_options, found, response)
            if _is_document(response):
                try:
                    meta = scan_meta(response.text()[:_MAX_BODY_SCAN])
                except Exception:
                    continue
                self._guarded(self._check_csp_and_framing, found, response, meta)
                self._guarded(self._check_referrer, found, response, meta)
                self._guarded(self._check_permissions, found, response)
        return found.findings()

    @staticmethod
    def _guarded(check, *args):
        """One failing check on one page must not hide the other checks or the other pages."""
        try:
            check(*args)
        except Exception:
            pass

    # -- individual checks -------------------------------------------------
    @staticmethod
    def _missing(response, header):
        return (f'GET {_u(response.url)} returned HTTP {response.status} without a {header} header '
                f'(headers received: {_header_names(response)}).')

    def _check_content_type_options(self, found, r):
        values = r.header_all('x-content-type-options')
        if not values:
            found.add('HDR-XCTO-MISSING', r.url, self._missing(r, 'X-Content-Type-Options'))
        elif values[0].split(',')[0].strip().lower() != 'nosniff':
            found.add('HDR-XCTO-INVALID', r.url,
                      f'GET {_u(r.url)} sent X-Content-Type-Options: "{_safe(values[0], 80)}"; only "nosniff" is valid.',
                      variant=values[0].strip().lower())

    def _check_csp_and_framing(self, found, r, meta):
        header_values = r.header_all('content-security-policy')
        valid_header = usable_policies(header_values)
        header_malformed = bool(header_values) and not valid_header
        report_only = r.header_all('content-security-policy-report-only')
        url = _u(r.url)
        # What was (not) sent, worded precisely: "absent" and "present but malformed" are different.
        sent = ('sent no Content-Security-Policy header' if not header_values
                else 'sent a Content-Security-Policy header with no valid policy')

        if header_malformed:
            shown = _safe(', '.join(header_values), 200) or '(empty)'
            found.add('HDR-CSP-MALFORMED', r.url,
                      f'GET {url} sent a Content-Security-Policy header ("{shown}") that contains no recognised '
                      f'CSP directive, so browsers apply no policy from it.')

        # Only a valid header policy or an EARLY meta policy protects the whole page. A late meta policy
        # protects just the content after it, so it never counts as full protection.
        full = valid_header + meta.early
        delivery = ('an HTTP header and a <meta> tag' if valid_header and meta.early
                    else 'a <meta> tag' if meta.early else 'an HTTP header')

        if full:
            weak_all, certain_all, reasons = True, True, []
            for policy in full:                     # all policies apply: weak only if EVERY one is weak
                details = _script_weaknesses(policy)
                if not details:
                    weak_all = False
                    break
                if not any(certain for _reason, certain in details):
                    certain_all = False
                reasons.extend(reason for reason, _c in details if reason not in reasons)
            if weak_all:
                value = _safe(', '.join(header_values + meta.raws), 300)
                found.add('HDR-CSP-UNSAFE', r.url,
                          f'GET {url}: the CSP delivered by {delivery} has a script policy that allows '
                          f'{"; ".join(reasons)}. Policy: {value}', variant=tuple(reasons), weight=len(reasons),
                          confidence='Confirmed' if certain_all else 'Potential')
            if meta.early and not valid_header:
                ignored = (f' The meta policy also contains {", ".join(meta.ignored)}, which browsers ignore in a '
                           f'<meta> tag.' if meta.ignored else '')
                found.add('HDR-CSP-META-ONLY', r.url,
                          f'GET {url} defines its Content-Security-Policy only in a <meta http-equiv> tag and '
                          f'{sent}.{ignored}')
        elif meta.late:
            found.add('HDR-CSP-META-LATE', r.url,
                      f'GET {url} {sent} and its only CSP is a <meta http-equiv> tag placed after '
                      f'{meta.blocker or "other content"}; a meta policy applies only to content '
                      f'parsed after it, so earlier content is not covered.')
        elif report_only:
            found.add('HDR-CSP-REPORT-ONLY', r.url,
                      f'GET {url} sent only Content-Security-Policy-Report-Only '
                      f'("{_safe(report_only[0], 200)}") and no enforcing policy.')
        elif not header_malformed:
            meta_note = (' A <meta http-equiv="Content-Security-Policy"> tag was found but contains no usable policy.'
                         if meta.unusable else ' No <meta http-equiv="Content-Security-Policy"> tag was found either.')
            found.add('HDR-CSP-MISSING', r.url, self._missing(r, 'Content-Security-Policy') + meta_note)

        self._check_framing(found, r, valid_header, meta, url)

    def _check_framing(self, found, r, valid_header, meta, url):
        """
        Clickjacking protection. Three different situations, which must not be confused:

        * frame-ancestors ABSENT from every header policy: no CSP restriction exists, so X-Frame-Options is
          consulted. (Absent is NOT the same as an empty directive.)
        * frame-ancestors PRESENT: it is enforced and browsers ignore X-Frame-Options, so X-Frame-Options is
          not consulted. Policies all apply, so one restrictive directive protects the page. A directive
          whose effective source list is empty ('none', empty, or all-invalid) matches no ancestor and
          blocks framing, i.e. it is restrictive. Only when EVERY present directive is permissive ('*' or a
          bare scheme source) is the page left framable: HDR-FRAME-ANCESTORS-WEAK.
        * frame-ancestors only in a <meta> CSP, a Report-Only header or a malformed header: browsers ignore
          it (scan_meta already removed it), so it counts as absent and is called out in the evidence.
        """
        present = [p['frame-ancestors'] for p in valid_header if 'frame-ancestors' in p]
        if present:
            if any(classify_frame_ancestors(tokens) == 'restrictive' for tokens in present):
                return
            value = _safe(' '.join(present[0]), 120)
            found.add('HDR-FRAME-ANCESTORS-WEAK', r.url,
                      f'GET {url} sent CSP frame-ancestors "{value}", which lets any site (or any site on that '
                      f'scheme) frame the page. X-Frame-Options is ignored by browsers while frame-ancestors is '
                      f'enforced.', variant='permissive')
            return
        meta_note = (' A frame-ancestors directive in a <meta> CSP is ignored by browsers, so it does not '
                     'protect against framing.' if 'frame-ancestors' in meta.ignored else '')
        xfo = r.header_all('x-frame-options')
        if not xfo:
            found.add('HDR-XFO-MISSING', r.url, self._missing(r, 'X-Frame-Options') +
                      ' No frame-ancestors directive in a Content-Security-Policy header is set either.' + meta_note)
        elif xfo[0].strip().upper() not in ('DENY', 'SAMEORIGIN'):
            found.add('HDR-XFO-WEAK', r.url,
                      f'GET {url} sent X-Frame-Options: "{_safe(xfo[0], 120)}"; only DENY or SAMEORIGIN are honoured '
                      f'by current browsers.' + meta_note, variant=xfo[0].strip().upper())

    def _check_hsts(self, found, r):
        if r.scheme != 'https':
            return                                  # browsers ignore HSTS received over HTTP
        values = r.header_all('strict-transport-security')
        if not values:
            if _is_success(r):                      # a gap is reported from full responses only
                found.add('HDR-HSTS-MISSING', r.url, self._missing(r, 'Strict-Transport-Security'))
            return
        max_age = parse_hsts_max_age(values[0])
        # Weights are tuples (tier, tiebreak) so different max-age values can never tie:
        # max-age=0 (HSTS switched off) > invalid header (HSTS not in force) > shorter lifetime.
        if max_age is None:
            found.add('HDR-HSTS-WEAK', r.url,
                      f'GET {_u(r.url)} sent Strict-Transport-Security: "{_safe(values[0], 120)}" which is not valid '
                      f'HSTS (no valid max-age, or a duplicate/invalid directive), so browsers ignore it.',
                      variant='invalid', weight=(2, 0))
        elif max_age < HSTS_MIN_SECONDS:
            note = ' (max-age=0 switches HSTS off)' if max_age == 0 else ''
            weight = (3, 0) if max_age == 0 else (1, -max_age)
            found.add('HDR-HSTS-WEAK', r.url,
                      f'GET {_u(r.url)} sent Strict-Transport-Security max-age={max_age}{note}, below the '
                      f'{HSTS_MIN_SECONDS}-second (180-day) minimum.', variant=max_age, weight=weight)

    def _check_referrer(self, found, r, meta):
        values = r.header_all('referrer-policy')
        if not values:
            if not meta.referrer:
                found.add('HDR-REFERRER-MISSING', r.url, self._missing(r, 'Referrer-Policy') +
                          ' No <meta name="referrer"> tag was found either.')
            return
        if effective_referrer_policy(values[0]) == 'unsafe-url':
            found.add('HDR-REFERRER-WEAK', r.url,
                      f'GET {_u(r.url)} sent Referrer-Policy: "{_safe(values[0], 120)}", which sends the full URL to '
                      f'all sites.', variant=values[0].strip().lower())

    def _check_permissions(self, found, r):
        if r.header_all('permissions-policy'):
            return
        if r.header_all('feature-policy'):
            note = (' Only the deprecated Feature-Policy header was found. It was superseded by Permissions-Policy, '
                    'uses a different syntax and is not treated as equivalent.')
        else:
            note = ' The deprecated Feature-Policy header is absent too.'
        found.add('HDR-PERMISSIONS-MISSING', r.url, self._missing(r, 'Permissions-Policy') + note)
