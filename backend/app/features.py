"""Feature extraction for the ML severity predictor."""
import math
import re

# Sigma rule category → numeric severity hint (used when no trained model exists)
SIGMA_SEVERITY = {
    "MAL-001": 3, "RAN-001": 4, "CMD-014": 4, "PS-001": 2,
    "BRUTE-002": 2, "WEB-001": 2, "WEB-002": 2, "SCAN-001": 1,
    "MEDIA-001": 0, "FIM-001": 1, "PRIV-001": 2, "POL-001": 1,
}

OS_ENCODING = {"windows": 0, "linux": 1, "router": 2}


def _os_class(os_type: str) -> str:
    if not os_type:
        return "linux"
    t = os_type.lower()
    if "windows" in t:
        return "windows"
    if "router" in t or "pfsense" in t:
        return "router"
    return "linux"


def extract_features(alert: dict) -> dict:
    """Convert a normalized alert into a feature dict for ML."""
    raw = str(alert.get("raw_log", "")).lower()
    desc = str(alert.get("description", "")).lower()

    # numeric n from raw logs (attempts, ports_scanned, size, count, bytes)
    n = 0
    m = re.search(r'"(?:attempts|ports_scanned|size|count|bytes|n)":\s*(\d+)', raw)
    if m:
        n = int(m.group(1))

    ts = alert.get("timestamp")
    hour = ts.hour if hasattr(ts, "hour") else 12
    day = ts.weekday() if hasattr(ts, "weekday") else 2

    sigma_id = alert.get("sigma_rule_id") or ""
    sigma_sev = SIGMA_SEVERITY.get(sigma_id, 1)

    script_exec = 1 if ("powershell" in raw or "-enc" in raw or "python3" in raw or "cmd.exe" in raw) else 0
    bytes_feature = min(1.0, math.log1p(n) / 10.0)

    return {
        "wazuh_level": float(alert.get("wazuh_level", 5)),
        "sigma_severity": float(sigma_sev),
        "agent_type": float(OS_ENCODING.get(_os_class(alert.get("os_type")), 1)),
        "hour_of_day": float(hour),
        "day_of_week": float(day),
        "script_execution": float(script_exec),
        "log_volume": float(bytes_feature),
        "prev_alerts_24h": float(alert.get("prev_alerts_24h", 0)),
    }


FEATURE_COLUMNS = [
    "wazuh_level",
    "sigma_severity",
    "agent_type",
    "hour_of_day",
    "day_of_week",
    "script_execution",
    "log_volume",
    "prev_alerts_24h",
]

SEVERITY_LABELS = ["low", "medium", "high", "critical"]


def severity_label(code: int) -> str:
    return SEVERITY_LABELS[min(max(code, 0), 3)]
