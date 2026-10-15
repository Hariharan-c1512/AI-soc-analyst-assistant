"""Shared helpers for the Streamlit frontend."""
import httpx
import pandas as pd

BACKEND_URL = "http://localhost:8000"


def api(method: str, path: str, **kwargs):
    url = f"{BACKEND_URL}{path}"
    return httpx.request(method, url, timeout=120, **kwargs)


def get_json(path: str):
    r = api("GET", path)
    r.raise_for_status()
    return r.json()


def post_json(path: str, payload: dict):
    r = api("POST", path, json=payload)
    r.raise_for_status()
    return r.json()


def fetch_alerts(params: dict | None = None) -> pd.DataFrame:
    data = get_json("/alerts" + _qs(params or {}))
    rows = []
    for a in data.get("items", []):
        rows.append({
            "id": a["id"],
            "alert_ref": a["alert_ref"],
            "timestamp": a["timestamp"],
            "agent": a["agent_name"],
            "severity": a["ml_severity"],
            "confidence": a["ml_confidence"],
            "rule": a["sigma_rule_id"] or "-",
            "wazuh_level": a["wazuh_level"],
            "description": (a["description"] or "")[:80],
            "mitre": a["mitre_technique_id"] or "-",
            "status": a["status"],
        })
    return pd.DataFrame(rows)


def _qs(params: dict) -> str:
    if not params:
        return ""
    return "?" + "&".join(f"{k}={v}" for k, v in params.items() if v not in (None, "", "All"))


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "#d0021b",
    "high": "#f5a623",
    "medium": "#f8e71c",
    "low": "#7ed321",
}
