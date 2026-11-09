"""Standardized finding model shared by every detector."""
import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .sanitize import sanitize_urls, scrub_text

SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Informational')
# Confirmed: the evidence directly proves the issue (e.g. a header is absent, a certificate is expired).
# Potential: a heuristic indicates the issue but cannot prove it.
# Informational: an observation, not a weakness by itself.
# "False positive" is deliberately NOT a scanner verdict: it is a triage state set by a person.
CONFIDENCES = ('Confirmed', 'Potential', 'Informational')
DEDUPE_SCOPES = ('host', 'url')     # site-wide issue vs issue specific to one URL
MAX_EVIDENCE_CHARS = 2000


def _normalize_url(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or '/', parts.query, ''))


@dataclass(repr=False)          # __repr__ is defined below: the generated one would print every field
class Finding:
    """
    URL handling (security): `affected_urls` holds the REAL crawled URLs and is the finding's INTERNAL page
    identity, needed for de-duplication and fingerprints (pages that differ only by query value must stay
    distinct). Treat it as internal: do not print, log, store or return it. Everything outward-facing uses
    the sanitized forms: `display_urls` / `display_url` / `affected_url`, `to_dict()` and `repr()`.
    Note that dataclasses.asdict() and vars() are not guarded and would expose the raw list. Flask's default
    JSON provider calls dataclasses.asdict() on dataclasses, so jsonify(finding) would leak it too: always
    serialize with to_dict() (tests/test_repr_exposure.py characterizes and guards this).
    """
    rule_id: str                    # stable identifier of the check, e.g. 'HDR-CSP-MISSING'
    title: str
    category: str                   # one of detectors.CATEGORIES
    severity: str
    confidence: str
    description: str
    affected_urls: list = field(repr=False)     # INTERNAL page identity (real URLs); never log or serialize raw
    evidence: str
    impact: str
    remediation: str
    reference: str                  # e.g. 'OWASP WSTG-CONF-07'
    detection_method: str           # e.g. 'Passive: response header inspection'
    dedupe_scope: str = 'host'
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f'Invalid severity {self.severity!r}')
        if self.confidence not in CONFIDENCES:
            raise ValueError(f'Invalid confidence {self.confidence!r}')
        if self.dedupe_scope not in DEDUPE_SCOPES:
            raise ValueError(f'Invalid dedupe scope {self.dedupe_scope!r}')
        if not self.affected_urls:
            raise ValueError('A finding needs at least one affected URL')
        if self.confidence == 'Confirmed' and not (self.evidence or '').strip():
            raise ValueError('A Confirmed finding must carry evidence')
        self.affected_urls = list(dict.fromkeys(self.affected_urls))
        self.evidence = (self.evidence or '')[:MAX_EVIDENCE_CHARS]

    @property
    def affected_url(self):
        """Primary affected page, SANITIZED (public). The raw URL is only available as affected_urls[0]."""
        return self.display_urls[0]

    @property
    def display_urls(self):
        """Sanitized URLs for display and serialization (one per internal URL, same order and count)."""
        return sanitize_urls(self.affected_urls)

    @property
    def display_url(self):
        return self.display_urls[0]

    def __repr__(self):
        # Built only from sanitized parts, so repr()/str()/format()/%s and logging a Finding, a list of
        # Findings or a ScanOutcome never print a raw URL, evidence, extra or any other free-text field.
        return (f'Finding(rule_id={self.rule_id!r}, severity={self.severity!r}, '
                f'confidence={self.confidence!r}, urls={self.display_urls!r})')

    def fingerprint(self):
        """
        Stable identity used for de-duplication and for promotion to the vulnerability list.
        Site-wide findings (scope 'host') are identified by rule + host:port; URL-specific
        findings by rule + normalized URL.
        """
        first = urlsplit(self.affected_urls[0])
        key = first.netloc.lower() if self.dedupe_scope == 'host' else _normalize_url(self.affected_urls[0])
        return hashlib.sha256(f'{self.rule_id}|{key}'.encode()).hexdigest()[:32]

    def to_dict(self):
        """
        Serialized form used by the API/UI. SECURITY: this is the single output guard, so every
        URL is sanitized (query values, fragments and credentials removed) and every text field is
        redacted and URL-scrubbed here, whatever a detector put into the Finding. The in-memory
        Finding keeps the original URLs as its internal page identity (url-scope fingerprints and
        de-duplication depend on them), so distinct pages are never merged; the sanitized list has
        the same length and order.
        """
        urls = self.display_urls
        return {
            'rule_id': self.rule_id, 'title': scrub_text(self.title), 'category': self.category,
            'severity': self.severity, 'confidence': self.confidence,
            'description': scrub_text(self.description), 'affected_urls': urls,
            'affected_url': urls[0], 'evidence': scrub_text(self.evidence),
            'impact': scrub_text(self.impact), 'remediation': scrub_text(self.remediation),
            'reference': scrub_text(self.reference), 'detection_method': scrub_text(self.detection_method),
            'fingerprint': self.fingerprint(),
        }
