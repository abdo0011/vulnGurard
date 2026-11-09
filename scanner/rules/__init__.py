"""
Rule catalog (catalog.py), severity classification (severity.py) and the finding builder that
joins them. Detectors describe WHAT they observed; this package decides how it is rated and
explained.
"""
from ..models import Finding
from .catalog import RULES, Rule
from .severity import assess, explain, overall_severity


def get_rule(rule_id):
    try:
        return RULES[rule_id]
    except KeyError:
        raise KeyError(f'Unknown rule {rule_id!r}')


def build_finding(rule_id, urls, evidence, confidence='Confirmed', instance=None, subject=None,
                  impact=None, likelihood=None, extra=None):
    """
    Create a standardized Finding from a catalog rule.

    instance  - distinguishes several findings of one rule on a host (e.g. a cookie or header name);
                it becomes part of the fingerprint ("RULE#instance") so they are not merged.
    subject   - text appended to the title (e.g. the cookie name).
    urls      - the real crawled URLs. They are the finding's INTERNAL page identity: de-duplication
                and url-scope fingerprints need them, so pages that differ only by query value stay
                distinct. They are never masked here; every outward-facing form (evidence text,
                Finding.display_urls, Finding.to_dict()) shows sanitized URLs instead.
    impact / likelihood - optional per-finding overrides of the rule defaults; the detector using
                them documents why. The override is recorded in finding.extra for transparency.
    """
    rule = get_rule(rule_id)
    impact = impact or rule.impact
    likelihood = likelihood or rule.likelihood
    info = {'rule': rule.id, 'impact': impact, 'likelihood': likelihood,
            'risk_before_confidence': overall_severity(impact, likelihood),
            'severity_explanation': explain(impact, likelihood, confidence)}
    info.update(extra or {})
    return Finding(
        rule_id=f'{rule.id}#{instance}' if instance else rule.id,
        title=f'{rule.title} ({subject})' if subject else rule.title,
        category=rule.category, severity=assess(impact, likelihood, confidence), confidence=confidence,
        description=rule.description, affected_urls=list(urls), evidence=evidence,
        impact=rule.impact_text, remediation=rule.remediation, reference=rule.reference,
        detection_method=rule.method, dedupe_scope=rule.dedupe_scope, extra=info)
