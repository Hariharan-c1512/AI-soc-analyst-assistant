"""Manually inject a security alert into the SOC assistant.

Lets you simulate an attack and watch it flow through the full pipeline
(Sigma → ML → MITRE → RAG → LLM) instantly.

Usage:
    python -m scripts.inject_alert --attack c2_beaconing
    python -m scripts.inject_alert --attack ssh_bruteforce --count 5
    python -m scripts.inject_alert --list
"""
import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.database import SessionLocal, init_db  # noqa: E402
from backend.app.ingester import process_alert  # noqa: E402
from backend.app.mock_data import (  # noqa: E402
    AGENTS, MALICIOUS_IPS, build_mock_alert,
)
from backend.app.models import Alert  # noqa: E402

ATTACKS = {
    "malware": "MAL-001",
    "ransomware": "RAN-001",
    "c2_beaconing": "CMD-014",
    "powershell": "PS-001",
    "ssh_bruteforce": "BRUTE-002",
    "web_shell": "WEB-001",
    "sql_injection": "WEB-002",
    "port_scan": "SCAN-001",
    "usb": "MEDIA-001",
    "fim": "FIM-001",
    "privilege_escalation": "PRIV-001",
}


def find_alert(sigma_rule_id: str) -> dict:
    """Generate an alert matching a specific attack template."""
    for i in range(1000):
        raw = build_mock_alert(20000 + i)
        if raw["sigma_rule_id"] == sigma_rule_id:
            return raw
    raise RuntimeError(f"No template found for {sigma_rule_id}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", choices=list(ATTACKS.keys()) + ["random"])
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list:
        print("Available attacks to inject:")
        for name, sigma in ATTACKS.items():
            print(f"  --attack {name:<20} (Sigma {sigma})")
        print("  --attack random")
        return

    if not args.attack:
        parser.error("use --list, --attack <name>, or --attack random")

    init_db()
    db = SessionLocal()
    try:
        base = int(time.time() * 1000)  # timestamp-based -> collision-free
        for i in range(args.count):
            if args.attack == "random":
                raw = build_mock_alert(base + i)
            else:
                raw = find_alert(ATTACKS[args.attack])
            raw["alert_ref"] = f"AL-{base + i}"
            alert = process_alert(db, raw)
            print(
                f"  [+] Injected {raw['description']:<45} -> "
                f"{alert.alert_ref} | {alert.ml_severity.upper():<8} | "
                f"{alert.mitre_technique_id} | agent {alert.agent_name}"
            )
    finally:
        db.close()
    print(f"\nInjected {args.count} alert(s). Refresh the dashboard at http://localhost:8501")


if __name__ == "__main__":
    main()
