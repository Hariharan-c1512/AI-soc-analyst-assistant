"""Validate Sigma rule matching against all alert templates.

This test proves the Sigma engine matches 100% of the attack templates
defined in mock_data.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.mock_data import TEMPLATES, build_mock_alert
from backend.app.sigma_engine import SigmaEngine


def test_all_templates_match_sigma():
    """Every alert template should match at least one Sigma rule."""
    engine = SigmaEngine()
    matched = 0
    total = len(TEMPLATES)
    results = []

    for i, tpl in enumerate(TEMPLATES):
        alert = build_mock_alert(10000 + i)
        rule = engine.match(alert)
        if rule:
            matched += 1
            results.append(f"  MATCH  {tpl.sigma_rule_id:<12} -> {rule.rule_id} ({rule.title})")
        else:
            results.append(f"  MISS   {tpl.sigma_rule_id:<12} -> no match")

    print(f"\nSigma Match Validation: {matched}/{total} templates matched")
    for r in results:
        print(r)

    assert matched == total, f"Only {matched}/{total} templates matched Sigma rules"


def test_sigma_rule_count():
    """Verify expected number of Sigma rules are loaded."""
    engine = SigmaEngine()
    print(f"\nSigma rules loaded: {len(engine.rules)}")
    assert len(engine.rules) >= 11, f"Expected >=11 rules, got {len(engine.rules)}"


def test_all_mock_alerts_match():
    """Generate 100 mock alerts and verify Sigma match rate."""
    engine = SigmaEngine()
    total = 100
    matched = 0

    for i in range(total):
        alert = build_mock_alert(30000 + i)
        rule = engine.match(alert)
        if rule:
            matched += 1

    pct = (matched / total) * 100
    print(f"\nMock Alert Sigma Match: {matched}/{total} ({pct:.1f}%)")
    assert matched == total, f"Only {matched}/{total} mock alerts matched"


if __name__ == "__main__":
    test_sigma_rule_count()
    test_all_templates_match_sigma()
    test_all_mock_alerts_match()
    print("\n=== ALL SIGMA VALIDATION TESTS PASSED ===")
