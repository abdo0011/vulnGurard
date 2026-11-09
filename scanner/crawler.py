"""
Bounded, same-host crawler (breadth-first, GET only).

Limits (approved): depth 2, 20 pages, and the client's 100-request budget. Only links that
pass the scope check are followed. Obvious state-changing paths (logout, delete ...) and
binary/static assets are skipped even though only GET is ever used.
"""
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin

from . import config as cfg
from .http_client import FetchError, HttpResponse, RequestBudgetExceeded
from .sanitize import sanitize_url
from .scope_validator import ScopeError, check_in_scope

_SKIP_EXTENSIONS = re.compile(
    r'\.(?:png|jpe?g|gif|svg|ico|webp|bmp|css|js|map|woff2?|ttf|eot|otf|pdf|zip|gz|tar|tgz|rar|7z|'
    r'mp3|mp4|avi|mov|wmv|webm|exe|dmg|iso|bin|docx?|xlsx?|pptx?)$', re.I)
_RISKY_PATH = re.compile(r'log[-_]?out|sign[-_]?out|log[-_]?off|delete|remove|destroy|unsubscribe', re.I)
_HTML_TYPES = ('text/html', 'application/xhtml+xml')


class _LinkParser(HTMLParser):
    """Collects navigation links only (a, area, frame, iframe). Never executes anything."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag in ('a', 'area') and attr.get('href'):
            self.links.append(attr['href'])
        elif tag in ('frame', 'iframe') and attr.get('src'):
            self.links.append(attr['src'])


def extract_links(html_text, base_url):
    parser = _LinkParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:               # malformed markup must never abort a scan
        pass
    out = []
    for href in parser.links[:500]:
        href = href.strip()
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            continue
        out.append(urldefrag(urljoin(base_url, href))[0])
    return out


@dataclass(repr=False)
class Page:
    url: str
    depth: int
    response: HttpResponse

    def __repr__(self):                 # representation only: sanitized URL, response repr is already safe
        return f'Page(url={sanitize_url(self.url)!r}, depth={self.depth!r}, response={self.response!r})'


@dataclass(repr=False)
class CrawlResult:
    pages: list = field(default_factory=list)
    skipped: list = field(default_factory=list)       # [(url, reason)]
    errors: list = field(default_factory=list)        # [(url, kind)]
    stopped_reason: object = None                     # e.g. 'request_budget'

    def __repr__(self):
        # skipped/errors hold raw URLs: show only counts and the machine-readable reason/kind codes.
        reasons = sorted({str(item[1]) for item in self.skipped if len(item) > 1})
        kinds = sorted({str(item[1]) for item in self.errors if len(item) > 1})
        return (f'CrawlResult(pages=<{len(self.pages)}>, skipped=<{len(self.skipped)}: {reasons}>, '
                f'errors=<{len(self.errors)}: {kinds}>, stopped_reason={self.stopped_reason!r})')


def crawl(client, start_url, max_depth=cfg.MAX_DEPTH, max_pages=cfg.MAX_PAGES, progress=None):
    """Crawl from start_url. The start page is always fetched; failures there are returned, not raised."""
    max_depth = min(max_depth, cfg.MAX_DEPTH)
    max_pages = min(max_pages, cfg.MAX_PAGES)
    result = CrawlResult()
    seen = set()
    queue = [(start_url, 0)]

    while queue and len(result.pages) < max_pages:
        url, depth = queue.pop(0)
        try:
            url = check_in_scope(url, client.origin, client.config)
        except ScopeError as exc:
            result.skipped.append((url, exc.code))
            continue
        if url in seen:
            continue
        seen.add(url)
        if depth > 0 and (_SKIP_EXTENSIONS.search(url.split('?')[0]) or _RISKY_PATH.search(url)):
            result.skipped.append((url, 'skipped_path'))
            continue

        try:
            resp = client.request('GET', url)
        except RequestBudgetExceeded:
            result.stopped_reason = 'request_budget'
            break
        except FetchError as exc:
            result.errors.append((url, exc.kind))
            if depth == 0 and exc.kind != 'tls_cert_invalid':
                break
            if depth == 0:
                # Certificate problems are findings for a later phase; still try to read the page.
                try:
                    resp = client.request('GET', url, verify_tls=False)
                except (FetchError, RequestBudgetExceeded):
                    break
            else:
                continue
        except ScopeError as exc:
            result.skipped.append((url, exc.code))
            continue

        for visited in [resp.url, *resp.redirect_chain]:
            seen.add(visited)
        result.pages.append(Page(url=resp.url, depth=depth, response=resp))
        if progress:
            progress(len(result.pages))

        if depth < max_depth and resp.status < 400 and resp.content_type in _HTML_TYPES:
            for link in extract_links(resp.text(), resp.url):
                if link not in seen:
                    queue.append((link, depth + 1))
    return result
