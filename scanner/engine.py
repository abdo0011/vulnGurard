"""
Minimal scan engine: validate -> crawl -> run detectors -> redact/dedupe -> outcome.

Phase 2 scope: purely in-memory. Persistence, background execution and the API are added in
later phases; the `progress` callback is the hook they will use so progress shown to users is
real (it reports actual counters, never estimates).
"""
import socket
from dataclasses import dataclass, field
from datetime import datetime

from . import config as cfg
from .crawler import crawl
from .detectors import get_detectors
from .http_client import RequestBudgetExceeded, ScanHTTPClient
from .models import SEVERITIES, Finding
from .result_processor import dedupe, redact
from .scope_validator import validate_scan_request

NOW_FMT = '%Y-%m-%d %H:%M:%S'

STAGES = ('validating', 'crawling', 'analysing', 'finalising', 'done')


@dataclass
class ScanContext:
    """Everything a detector may use. Network access goes through `client` only."""
    target: object
    pages: list
    client: object
    config: object
    crawl_result: object = None


@dataclass
class ScanOutcome:
    target: str
    status: str = 'running'            # completed | completed_with_errors | failed
    stage: str = 'validating'
    findings: list = field(default_factory=list)
    pages_crawled: int = 0
    requests_used: int = 0
    checks_done: int = 0
    checks_total: int = 0
    errors: list = field(default_factory=list)     # safe, user-displayable strings
    notes: list = field(default_factory=list)
    started_at: str = ''
    completed_at: str = ''

    def severity_counts(self):
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}


class ScanEngine:
    def __init__(self, config=None, resolver=socket.getaddrinfo, client_factory=None):
        self._config = config
        self._resolver = resolver
        self._client_factory = client_factory or ScanHTTPClient

    def run(self, url, authorized, categories=None, progress=None):
        """
        Run a scan. Raises ScopeError (bad/unauthorized/out-of-scope target) or ValueError
        (unknown category) BEFORE any request is made; every later problem is reported in the
        returned outcome instead of raising.
        """
        config = self._config or cfg.load_config()
        target = validate_scan_request(url, authorized, config, self._resolver)
        detectors = get_detectors(categories)

        out = ScanOutcome(target=target.url, started_at=datetime.now().strftime(NOW_FMT),
                          checks_total=len(detectors) + 1)   # +1 for the crawl itself

        def report(stage):
            out.stage = stage
            if progress:
                progress(stage, out.checks_done, out.checks_total, len(out.findings))

        report('validating')
        client = self._client_factory(target, config, resolver=self._resolver)

        report('crawling')
        crawl_result = crawl(client, target.url)
        out.checks_done += 1
        out.pages_crawled = len(crawl_result.pages)
        if crawl_result.stopped_reason == 'request_budget':
            out.notes.append('Crawl stopped: request limit reached.')
        if not crawl_result.pages:
            kinds = sorted({kind for _u, kind in crawl_result.errors}) or ['no_response']
            out.errors.append(f'The target could not be fetched ({", ".join(kinds)}).')
            return self._finish(out, client, 'failed', report)

        context = ScanContext(target=target, pages=crawl_result.pages, client=client,
                              config=config, crawl_result=crawl_result)
        report('analysing')
        raw = []
        for detector in detectors:
            try:
                results = detector.run(context)
                for item in results or []:
                    if isinstance(item, Finding):
                        raw.append(item)
                    else:
                        out.errors.append(f'{detector.name}: returned an invalid result and it was ignored.')
            except RequestBudgetExceeded:
                out.notes.append(f'{detector.name}: stopped early, request limit reached.')
            except Exception as exc:    # one broken detector must not abort the scan
                # Only the exception class is exposed; details could leak internals.
                out.errors.append(f'{detector.name}: failed ({type(exc).__name__}).')
            out.checks_done += 1
            out.findings = dedupe(raw)
            report('analysing')

        report('finalising')
        for f in out.findings:
            f.evidence = redact(f.evidence)
        status = 'completed_with_errors' if out.errors else 'completed'
        return self._finish(out, client, status, report)

    @staticmethod
    def _finish(out, client, status, report):
        out.status = status
        out.requests_used = client.requests_made
        out.completed_at = datetime.now().strftime(NOW_FMT)
        report('done')
        return out
