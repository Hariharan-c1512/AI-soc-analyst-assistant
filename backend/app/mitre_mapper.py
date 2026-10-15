"""MITRE ATT&CK mapping.

Maps (Wazuh rule_id + Sigma rule_id) to MITRE tactic/technique using a local
lookup table. In production this can be extended with the official STIX feed
(attackcti) for richer technique metadata.
"""
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Lookup: sigma_rule_id -> {tactic, tactic_id, technique, technique_id, kill_chain}
MAP: dict[str, dict] = {
    "MAL-001": {
        "tactic": "Execution", "tactic_id": "TA0002",
        "technique": "User Execution: Malicious File", "technique_id": "T1204.002",
        "kill_chain": "Execution",
    },
    "RAN-001": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact", "technique_id": "T1486",
        "kill_chain": "Impact",
    },
    "CMD-014": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Application Layer Protocol: Web Protocols", "technique_id": "T1071.001",
        "kill_chain": "Command and Control",
    },
    "PS-001": {
        "tactic": "Execution", "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter: PowerShell", "technique_id": "T1059.001",
        "kill_chain": "Execution",
    },
    "BRUTE-002": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Brute Force", "technique_id": "T1110",
        "kill_chain": "Initial Access",
    },
    "WEB-001": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique": "Server Software Component: Web Shell", "technique_id": "T1505.003",
        "kill_chain": "Installation",
    },
    "WEB-002": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application", "technique_id": "T1190",
        "kill_chain": "Initial Access",
    },
    "SCAN-001": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network Service Discovery", "technique_id": "T1046",
        "kill_chain": "Reconnaissance",
    },
    "MEDIA-001": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique": "Replication Through Removable Media", "technique_id": "T1091",
        "kill_chain": "Initial Access",
    },
    "FIM-001": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": "Indicator Removal on Host: File Deletion", "technique_id": "T1070.001",
        "kill_chain": "Defense Evasion",
    },
    "PRIV-001": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Exploitation for Privilege Escalation", "technique_id": "T1068",
        "kill_chain": "Exploitation",
    },
    "POL-001": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": "Valid Accounts", "technique_id": "T1078",
        "kill_chain": "Defense Evasion",
    },
}


def map_alert(alert: dict) -> dict:
    """Return MITRE dict for an alert (empty dict if unmapped)."""
    sigma_id = alert.get("sigma_rule_id") or ""
    entry = MAP.get(sigma_id)
    if entry:
        return dict(entry)
    # Fallback: derive from raw_log description heuristics
    desc = f"{alert.get('description','')} {alert.get('raw_log','')}".lower()
    if "sql" in desc:
        return dict(MAP["WEB-002"])
    if "port" in desc or "scan" in desc:
        return dict(MAP["SCAN-001"])
    if "malware" in desc or "eicar" in desc:
        return dict(MAP["MAL-001"])
    return {}


def load_attack_json(path: Optional[str] = None) -> dict:
    """Load a local MITRE STIX/JSON file for enrichment (optional)."""
    p = Path(path) if path else None
    if p and p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:  # pragma: no cover
            logger.warning("Failed to load ATT&CK JSON: %s", e)
    return {}
