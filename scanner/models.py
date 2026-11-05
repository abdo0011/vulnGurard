"""Standardized finding model shared by every detector."""
import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

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


@dataclass
class Finding:
    rule_id: str                    # stable identifier of the check, e.g. 'HDR-CSP-MISSING'
    title: str
    category: str                   # one of detectors.CATEGORIES
    severity: str
    confidence: str
    description: str
    affected_urls: list
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
        return self.affected_urls[0]

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
        return {
            'rule_id': self.rule_id, 'title': self.title, 'category': self.category,
            'severity': self.severity, 'confidence': self.confidence,
            'description': self.description, 'affected_urls': self.affected_urls,
            'affected_url': self.affected_url, 'evidence': self.evidence,
            'impact': self.impact, 'remediation': self.remediation,
            'reference': self.reference, 'detection_method': self.detection_method,
            'fingerprint': self.fingerprint(),
        }
