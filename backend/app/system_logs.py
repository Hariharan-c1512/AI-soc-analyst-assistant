"""System-log based detection — reads journald/syslog and converts real events
into alerts. Used with INGESTION_MODE=system so manual attacks on the machine
produce live detections without needing Wazuh.

Detection rules (configurable):
  - SSH brute force  : >=5 "Failed password" for same (user, src) in window
  - Auth failures    : authentication failure events
  - Sudo misuse      : sudo authentication failures / NOT in sudoers
  - User changes     : new user / user deleted
  - Service stop     : systemd service stopped unexpectedly
"""
import logging
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)


def read_journal(since: datetime, max_entries: int = 500) -> list[dict]:
    """Fetch journal entries since a timestamp via journalctl."""
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    try:
        out = subprocess.run(
            ["journalctl", "--since", since_str, "--no-pager", "-o", "short-iso", "-n", str(max_entries)],
            capture_output=True, text=True, timeout=20,
        )
        entries = []
        for line in out.stdout.splitlines():
            # short-iso format: 2026-08-12T02:45:01+0530 host COMM[pid]: message
            m = re.match(r"(\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{4})\s+(\S+)\s+([^\[]+)\[?(\d+)?\]?:\s?(.*)", line)
            if not m:
                continue
            try:
                ts = datetime.fromisoformat(m.group(1))
            except ValueError:
                continue
            entries.append({
                "timestamp": ts,
                "host": m.group(2),
                "comm": m.group(3).strip(),
                "pid": m.group(4),
                "message": m.group(5),
            })
        return entries
    except Exception as e:  # pragma: no cover
        logger.warning("journalctl failed: %s", e)
        return []


def detect_events(entries: list[dict]) -> list[dict]:
    """Convert raw journal entries into normalized alert candidates."""
    alerts: list[dict] = []
    failed_ssh: dict[tuple, list] = defaultdict(list)

    for e in entries:
        msg = e["message"]
        ts = e["timestamp"]

        # --- SSH brute force ---
        if "Failed password" in msg:
            m = re.search(r"for (?:invalid user )?(\S+) from (\S+) port", msg)
            if m:
                key = (m.group(1), m.group(2))
                failed_ssh[key].append(ts)
            continue

        # --- Sudo misuse / auth failures ---
        if ("authentication failure" in msg and ("sudo" in msg or "sudo" == e["comm"])) or \
           "incorrect password attempts" in msg and "sudo" in msg:
            alerts.append({
                "description": "Sudo authentication failure (possible misuse)",
                "sigma_rule_id": "PRIV-001",
                "sigma_title": "Sudo Privilege Escalation",
                "wazuh_rule_id": 5901, "wazuh_level": 9,
                "mitre_tactic": "Privilege Escalation", "mitre_tactic_id": "TA0004",
                "mitre_technique": "Exploitation for Privilege Escalation", "mitre_technique_id": "T1068",
                "kill_chain_phase": "Exploitation",
                "raw_log": msg, "os_type": "Linux", "source": "system",
            })
            continue
        if "NOT in sudoers" in msg:
            alerts.append({
                "description": "Unauthorized user attempted sudo",
                "sigma_rule_id": "PRIV-001",
                "sigma_title": "Sudo Privilege Escalation",
                "wazuh_rule_id": 5901, "wazuh_level": 10,
                "mitre_tactic": "Privilege Escalation", "mitre_tactic_id": "TA0004",
                "mitre_technique": "Exploitation for Privilege Escalation", "mitre_technique_id": "T1068",
                "kill_chain_phase": "Exploitation",
                "raw_log": msg, "os_type": "Linux", "source": "system",
            })
            continue
        if "authentication failure" in msg:
            alerts.append({
                "description": "System authentication failure",
                "sigma_rule_id": "BRUTE-002",
                "sigma_title": "SSH Brute Force",
                "wazuh_rule_id": 5753, "wazuh_level": 8,
                "mitre_tactic": "Credential Access", "mitre_tactic_id": "TA0006",
                "mitre_technique": "Brute Force", "mitre_technique_id": "T1110",
                "kill_chain_phase": "Initial Access",
                "raw_log": msg, "os_type": "Linux", "source": "system",
            })
            continue

        # --- User changes ---
        if re.search(r"(^|[\s:])(new user:|useradd|userdel|del user)", msg):
            alerts.append({
                "description": "User account changed (created/deleted)",
                "sigma_rule_id": "POL-001",
                "sigma_title": "Valid Accounts",
                "wazuh_rule_id": 5501, "wazuh_level": 7,
                "mitre_tactic": "Defense Evasion", "mitre_tactic_id": "TA0005",
                "mitre_technique": "Valid Accounts", "mitre_technique_id": "T1078",
                "kill_chain_phase": "Persistence",
                "raw_log": msg, "os_type": "Linux", "source": "system",
            })
            continue

    # Emit brute-force alerts once threshold crossed
    now = datetime.now(timezone.utc)
    for (user, src), times in failed_ssh.items():
        recent = [t for t in times if t >= now - BRUTE_FORCE_WINDOW]
        if len(recent) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "description": f"SSH brute force detected — {len(recent)} failed logins for {user}",
                "sigma_rule_id": "BRUTE-002",
                "sigma_title": "SSH Brute Force",
                "wazuh_rule_id": 5753, "wazuh_level": 10,
                "mitre_tactic": "Credential Access", "mitre_tactic_id": "TA0006",
                "mitre_technique": "Brute Force", "mitre_technique_id": "T1110",
                "kill_chain_phase": "Initial Access",
                "raw_log": f"Failed password for {user} from {src} (x{len(recent)})",
                "os_type": "Linux", "source": "system",
            })
    return alerts


class SystemLogTailer:
    """Polls journald periodically and returns new events."""

    def __init__(self):
        self._last_check = datetime.now(timezone.utc) - timedelta(seconds=10)
        self._seen: set[str] = set()

    def poll(self) -> list[dict]:
        entries = read_journal(self._last_check)
        if entries:
            self._last_check = max(e["timestamp"] for e in entries)
        # Deduplicate by (timestamp, comm, message)
        new_entries = []
        for e in entries:
            key = f"{e['timestamp'].isoformat()}|{e.get('comm')}|{e.get('message', '')[:120]}"
            if key not in self._seen:
                self._seen.add(key)
                new_entries.append(e)
        if len(self._seen) > 20000:
            self._seen = set(list(self._seen)[-10000:])
        return new_entries
