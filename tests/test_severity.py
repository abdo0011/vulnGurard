import pytest

from scanner.models import CONFIDENCES, SEVERITIES
from scanner.rules import RULES, build_finding, get_rule
from scanner.rules.severity import apply_confidence, assess, explain, lower, overall_severity
from scanner.detectors import CATEGORIES

MATRIX = {
    ('High', 'Low'): 'Medium', ('High', 'Medium'): 'High', ('High', 'High'): 'Critical',
    ('Medium', 'Low'): 'Low', ('Medium', 'Medium'): 'Medium', ('Medium', 'High'): 'High',
    ('Low', 'Low'): 'Informational', ('Low', 'Medium'): 'Low', ('Low', 'High'): 'Medium',
}


@pytest.mark.parametrize('key,expected', MATRIX.items())
def test_matrix_matches_documentation(key, expected):
    likelihood, impact = key
    assert overall_severity(impact, likelihood) == expected


def test_invalid_levels_rejected():
    with pytest.raises(ValueError):
        overall_severity('Severe', 'Low')


def test_confidence_adjustments():
    assert apply_confidence('Critical', 'Confirmed') == 'Critical'
    assert apply_confidence('Low', 'Confirmed') == 'Low'
    assert apply_confidence('High', 'Informational') == 'Informational'
    # Potential: cap at Medium, never raise lower severities
    assert apply_confidence('Critical', 'Potential') == 'Medium'
    assert apply_confidence('High', 'Potential') == 'Medium'
    assert apply_confidence('Medium', 'Potential') == 'Medium'
    assert apply_confidence('Low', 'Potential') == 'Low'
    assert apply_confidence('Informational', 'Potential') == 'Informational'
    with pytest.raises(ValueError):
        apply_confidence('Severe', 'Confirmed')


def test_potential_findings_are_capped_at_medium():
    for sev in SEVERITIES:
        out = apply_confidence(sev, 'Potential')
        assert SEVERITIES.index(out) >= SEVERITIES.index('Medium'), (sev, out)


def test_lower():
    assert [lower(x) for x in ('High', 'Medium', 'Low')] == ['Medium', 'Low', 'Low']


def test_every_rule_is_well_formed_and_has_complete_guidance():
    assert len(RULES) >= 40
    for rule in RULES.values():
        assert rule.category in CATEGORIES, rule.id
        assert rule.impact in ('Low', 'Medium', 'High') and rule.likelihood in ('Low', 'Medium', 'High'), rule.id
        for field in ('title', 'description', 'impact_text', 'remediation', 'reference', 'method'):
            assert len(getattr(rule, field)) > 15, (rule.id, field)
        assert 'OWASP' in rule.reference, rule.id
        assert rule.dedupe_scope in ('host', 'url')
    for cat in CATEGORIES:
        assert any(r.category == cat for r in RULES.values()), cat


def test_build_finding_has_every_required_field_and_no_cvss():
    f = build_finding('HDR-CSP-MISSING', ['http://a.test/'], 'header absent')
    d = f.to_dict()
    for key in ('title', 'category', 'severity', 'confidence', 'detection_method', 'evidence', 'impact',
                'remediation', 'reference', 'description', 'affected_url', 'fingerprint'):
        assert d[key], key
    assert not any('cvss' in k.lower() for k in list(d) + list(f.extra))
    assert (f.severity, f.confidence) == ('Medium', 'Confirmed')
    assert f.extra['rule'] == 'HDR-CSP-MISSING' and f.extra['risk_before_confidence'] == 'Medium'


def test_instance_keeps_fingerprints_apart_and_overrides_work():
    a = build_finding('COOKIE-NO-HTTPONLY', ['http://a.test/'], 'e', instance='sid', subject='sid')
    b = build_finding('COOKIE-NO-HTTPONLY', ['http://a.test/'], 'e', instance='theme', subject='theme',
                      likelihood=lower(get_rule('COOKIE-NO-HTTPONLY').likelihood))
    assert a.fingerprint() != b.fingerprint() and a.title.endswith('(sid)')
    assert (a.severity, b.severity) == ('Medium', 'Low')


def test_potential_confidence_never_exceeds_medium_via_build_finding():
    f = build_finding('INFO-SECRET-EXPOSED', ['http://a.test/'], 'pattern matched', confidence='Potential')
    assert f.severity == 'Medium'
    f = build_finding('INFO-SECRET-EXPOSED', ['http://a.test/'], 'pattern matched', confidence='Confirmed')
    assert f.severity == 'High'
    f = build_finding('INFO-TECH-DISCLOSURE', ['http://a.test/'], 'Server: nginx', confidence='Informational')
    assert f.severity == 'Informational'


def test_unknown_rule_raises():
    with pytest.raises(KeyError):
        build_finding('NOPE', ['http://a.test/'], 'x')


def test_explanations_describe_every_kind_of_decision():
    assert explain('Medium', 'Low', 'Confirmed') == 'Impact Medium x likelihood Low rates Low; confidence Confirmed, no adjustment.'
    assert 'capped to Medium' in explain('High', 'High', 'Potential')
    assert 'Informational' in explain('High', 'High', 'Informational')
    assert 'no adjustment' in explain('Low', 'Low', 'Potential')       # nothing to cap


def test_build_finding_records_the_severity_explanation():
    f = build_finding('HDR-HSTS-MISSING', ['https://a.test/'], 'header absent')
    assert f.extra['severity_explanation'] == explain('Medium', 'Low', 'Confirmed')
    assert f.severity == 'Low'


def test_severity_module_is_independent_of_detectors_and_findings():
    import scanner.rules.severity as sev
    assert not hasattr(sev, 'Finding') and not hasattr(sev, 'build_finding')
