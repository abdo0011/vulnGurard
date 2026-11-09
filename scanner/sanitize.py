"""
Sanitization of URLs and free text before they are stored or serialized.

Crawled URLs can carry secrets (session ids, signatures, OAuth fragments, userinfo). A finding only
needs to identify the page, so everything that could be a secret is masked and the rest is kept:

    kept    scheme, host, port, path
    masked  every query VALUE (parameter names are kept), path parameters (";jsessionid=..."),
            bare query tokens
    removed fragment and userinfo

The result is deterministic and idempotent: sanitize_url(sanitize_url(u)) == sanitize_url(u).
Limitation: a secret embedded in the URL PATH itself (e.g. /reset/<token>) cannot be recognised
in general; only JWT-, AWS-key- and similar shapes caught by result_processor.redact are masked.
"""
import re
from urllib.parse import urlsplit

MASK = '[redacted]'
_URL_IN_TEXT = re.compile(r'https?://[^\s"\'<>]+', re.I)
_TRAILING = '.,;:)'
_PATH_PARAM = re.compile(r';([^/;=?#]+)=[^/;?#]*')


def sanitize_url(url):
    """URL that still identifies the page but carries no query values, fragment or credentials."""
    from .result_processor import redact
    url = (url or '').strip()
    try:
        parts = urlsplit(url)
        host = parts.hostname or ''
        if ':' in host:
            host = f'[{host}]'                      # IPv6 literal
        port = f':{parts.port}' if parts.port else ''
    except ValueError:                              # malformed URL: keep only what precedes ?/#
        return redact(re.split(r'[?#]', url, maxsplit=1)[0])
    path = _PATH_PARAM.sub(lambda m: f';{m.group(1)}={MASK}', parts.path)
    out = f'{parts.scheme}://{host}{port}{redact(path)}' if parts.scheme else redact(path)
    if parts.query:
        pairs = []
        for item in parts.query.split('&'):
            if not item:
                continue
            name, sep, _value = item.partition('=')
            pairs.append(f'{name}={MASK}' if sep else MASK)
        out += '?' + '&'.join(pairs)
    return out


def sanitize_urls(urls):
    """
    Sanitize a list of URLs for display. Order AND length are preserved: pages that differ only by a
    masked query value show the same text, but each page is still listed, so a count is never silently
    reduced. (Identity for de-duplication/fingerprints is the original URL, kept inside Finding.)
    """
    return [sanitize_url(u) for u in urls]


def scrub_text(text):
    """Redact secrets in free text and sanitize every URL embedded in it."""
    from .result_processor import redact

    def _one(match):
        raw = match.group(0)
        stripped = raw.rstrip(_TRAILING)
        return sanitize_url(stripped) + raw[len(stripped):]
    return redact(_URL_IN_TEXT.sub(_one, text or ''))
