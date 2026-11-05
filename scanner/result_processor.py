"""Post-processing of detector output: redaction of sensitive evidence and de-duplication."""
import re

# SECURITY: evidence is stored and shown in the UI, so anything resembling a secret or personal
# data is masked before a Finding is persisted. Patterns are intentionally broad.
_REDACTIONS = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)', re.S), '[REDACTED PRIVATE KEY]'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*'), '[REDACTED JWT]'),
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), '[REDACTED AWS KEY]'),
    (re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}'), r'\1 [REDACTED]'),
    (re.compile(r'(?i)\b((?:api[_-]?key|secret|token|passwd|password|pwd|auth|session(?:id)?)["\']?\s*[:=]\s*["\']?)[^\s"\'&;,]{4,}'), r'\1[REDACTED]'),
    (re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'), '[REDACTED EMAIL]'),
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[REDACTED NUMBER]'),
]


def redact(text):
    text = text or ''
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def dedupe(findings):
    """
    Merge findings that share a fingerprint, keeping the first and combining affected URLs.
    Input order is preserved. If duplicates disagree, the strongest severity wins.
    """
    from .models import SEVERITIES
    merged = {}
    for f in findings:
        fp = f.fingerprint()
        if fp not in merged:
            merged[fp] = f
            continue
        kept = merged[fp]
        kept.affected_urls = list(dict.fromkeys(kept.affected_urls + f.affected_urls))
        if SEVERITIES.index(f.severity) < SEVERITIES.index(kept.severity):
            kept.severity = f.severity
    return list(merged.values())
