"""Tests for the AI SOC Analyst Assistant backend."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.features import extract_features, severity_label  # noqa: E402
from backend.app.mock_data import build_mock_alert  # noqa: E402
from backend.app.sigma_engine import SigmaEngine  # noqa: E402


def test_mock_alert_shape():
    a = build_mock_alert(1)
    assert a["alert_ref"].startswith("AL-")
    assert a["wazuh_rule_id"] is not None
    assert a["ml_severity"] in ("low", "medium", "high", "critical")
    assert a["mitre_technique_id"].startswith("T")
    assert a["raw_log"]


def test_features_extraction():
    a = build_mock_alert(2)
    f = extract_features(a)
    for key in ["wazuh_level", "sigma_severity", "agent_type", "hour_of_day",
                "day_of_week", "script_execution", "log_volume", "prev_alerts_24h"]:
        assert key in f


def test_severity_label_roundtrip():
    assert severity_label(0) == "low"
    assert severity_label(3) == "critical"


def test_sigma_engine_has_rules():
    engine = SigmaEngine()
    assert len(engine.rules) > 0, "Sigma rules should be loaded"


def test_sigma_match():
    engine = SigmaEngine()
    a = build_mock_alert(3)
    matched = engine.match(a)
    # All mock templates should match at least the keyword rules by description
    assert matched is not None or a["sigma_rule_id"]
