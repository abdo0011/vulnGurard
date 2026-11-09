"""
Severity classification: documented, deterministic, evidence-based (OWASP Risk Rating, simplified).

This module is pure classification logic. It knows nothing about detectors, HTTP or findings, so
severity policy can be changed in one place without touching any detector.

Overall severity = f(likelihood, impact), each rated Low / Medium / High:

                      IMPACT
    LIKELIHOOD |  Low           Medium    High
    -----------+-----------------------------------
    High       |  Medium        High      Critical
    Medium     |  Low           Medium    High
    Low        |  Informational Low       Medium

Impact     = damage if the weakness is abused (what an attacker gains).
Likelihood = how likely abuse is, given exposure and how little effort it takes.

Confidence then adjusts the result so uncertain evidence never produces alarming ratings:
  * Confirmed      - no adjustment.
  * Potential      - capped at Medium (a heuristic match alone is never High or Critical).
  * Informational  - always Informational (an observation, not a weakness by itself).

Where a rule distinguishes sensitive from ordinary targets (e.g. session-like cookie names) the
likelihood is lowered one step for the ordinary case with lower().

CVSS: deliberately not produced. None of the passive/configuration checks maps to a verified CVSS
vector, and scores are never invented.
"""
from ..models import SEVERITIES

LEVELS = ('Low', 'Medium', 'High')

_MATRIX = {            # (likelihood, impact) -> severity
    ('High', 'Low'): 'Medium', ('High', 'Medium'): 'High', ('High', 'High'): 'Critical',
    ('Medium', 'Low'): 'Low', ('Medium', 'Medium'): 'Medium', ('Medium', 'High'): 'High',
    ('Low', 'Low'): 'Informational', ('Low', 'Medium'): 'Low', ('Low', 'High'): 'Medium',
}


def lower(level):
    """One step lower on the Low/Medium/High scale (Low stays Low)."""
    return LEVELS[max(0, LEVELS.index(level) - 1)]


def overall_severity(impact, likelihood):
    if impact not in LEVELS or likelihood not in LEVELS:
        raise ValueError(f'impact/likelihood must be one of {LEVELS}')
    return _MATRIX[(likelihood, impact)]


def apply_confidence(severity, confidence):
    if severity not in SEVERITIES:
        raise ValueError(f'Unknown severity {severity!r}')
    if confidence == 'Informational':
        return 'Informational'
    if confidence == 'Potential' and SEVERITIES.index(severity) < SEVERITIES.index('Medium'):
        return 'Medium'                      # cap: Critical/High -> Medium
    return severity


def assess(impact, likelihood, confidence):
    return apply_confidence(overall_severity(impact, likelihood), confidence)


def explain(impact, likelihood, confidence):
    """A one-sentence, human-readable justification of the severity decision."""
    base = overall_severity(impact, likelihood)
    final = apply_confidence(base, confidence)
    text = f'Impact {impact} x likelihood {likelihood} rates {base}'
    if confidence == 'Informational':
        return f'{text}; the evidence is an observation rather than a weakness, so the finding is Informational.'
    if final != base:
        return f'{text}; capped to {final} because the evidence is heuristic (Potential).'
    return f'{text}; confidence {confidence}, no adjustment.'
