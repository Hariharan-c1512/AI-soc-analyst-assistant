"""Auto-generate Sigma YAML rules from alerts stored in the database.

Analyzes each distinct Sigma title in the DB, derives discriminating keywords
from the descriptions/raw logs, pairs them with MITRE techniques from the
mitre_mapper MAP table, and writes a compact Sigma rule YAML file per title.

Usage:
    python -m scripts.generate_sigma_rules [--rules-dir backend/sigma_rules] [--overwrite]

This script reads the existing DB (populated via seed_data or mock ingestion)
and produces rules for every alert type it finds that is not already covered
by a matching rule id.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.database import SessionLocal, init_db  # noqa: E402
from backend.app.models import Alert  # noqa: E402
from backend.app.mitre_mapper import MAP  # noqa: E402

KNOWN_TITLE_TO_ID = {
    "Malware Detected by AntiVirus": "MAL-001",
    "Ransomware File Encryption Pattern": "RAN-001",
    "Suspicious Outbound Connection to C2 IP": "CMD-014",
    "Suspicious PowerShell Command Line": "PS-001",
    "SSH Brute Force": "BRUTE-002",
    "Web Shell Upload Attempt": "WEB-001",
    "SQL Injection Attempt": "WEB-002",
    "Network Port Scan": "SCAN-001",
    "USB Device Connected": "MEDIA-001",
    "File Integrity Monitoring Change": "FIM-001",
    "Sudo Privilege Escalation": "PRIV-001",
}

MITRE_TACTIC_KEYWORDS = {
    "Execution": "attack.execution",
    "Impact": "attack.impact",
    "Command and Control": "attack.command-and-control",
    "Credential Access": "attack.credential-access",
    "Persistence": "attack.persistence",
    "Initial Access": "attack.initial-access",
    "Discovery": "attack.discovery",
    "Defense Evasion": "attack.defense-evasion",
    "Privilege Escalation": "attack.privilege-escalation",
}

# Per-rule fallback keyword sets in case DB raw logs are generic
RULE_KEYWORDS = {
    "MAL-001": ["clamav", "eicar", "malware", "virus", "found"],
    "RAN-001": ["ransomware", ".locked", "encryption", "bulk file", ".crypt"],
    "CMD-014": ["c2", "command and control", "beacon", "malicious ip", "outbound"],
    "PS-001": ["powershell", "-enc", "encodedcommand", "cmd.exe", "bypass"],
    "BRUTE-002": ["brute force", "failed ssh", "failed login", "attempts"],
    "WEB-001": ["web shell", "shell.php", ".php", "upload", "webshell"],
    "WEB-002": ["sql injection", "' or '1'='1", "select ", "union select", "sqlmap"],
    "SCAN-001": ["port scan", "ports_scanned", "sweep", "nmap", "scan"],
    "MEDIA-001": ["usb", "usbstor", "removable", "san"],
    "FIM-001": ["integrity", "modified", "checksum", "fim", "filedelete"],
    "PRIV-001": ["sudo", "privilege escalation", "/bin/su", "sudoers"],
}

GOOD_FIELD_CANDIDATES = re.compile(r'"(\w+)":\s*\??')


def _dedupe_keep_order(items):
    out = []
    for i in items:
        if i not in out:
            out.append(i)
    return out


def _build_keywords(title, raw_log_texts):
    kws = list(RULE_KEYWORDS.get(KNOWN_TITLE_TO_ID.get(title, ""), []))
    text = " ".join(raw_log_texts).lower()
    for token in [
        "clamav", "eicar", "malware", "ransomware", "powershell", "brute force",
        "failed ssh", "web shell", "sql injection", "port scan", "usb", "sudo",
        "integrity", "c2", "beacon", ".locked", "shell.php", "login",
    ]:
        if token in text and token not in kws:
            kws.append(token)
    return _dedupe_keep_order(kws)[:6]


def _snake(title):
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s


def _fields(raw_log_texts):
    fields = []
    for t in raw_log_texts:
        for m in GOOD_FIELD_CANDIDATES.finditer(t):
            f = m.group(1)
            if f not in fields:
                fields.append(f)
    return fields[:6]


def _rule_id(title, used_ids):
    prefix = (re.sub(r"[^A-Z]", "", title) or "GEN")[:3].upper()
    n = 1
    rid = f"AUTO-{prefix}-{n:03d}"
    while rid in used_ids:
        n += 1
        rid = f"AUTO-{prefix}-{n:03d}"
    used_ids.add(rid)
    return rid


def generate(title, raw_log_texts, mitre, used_ids):
    rid = _rule_id(title, used_ids)
    kws = _build_keywords(title, raw_log_texts)
    fields = _fields(raw_log_texts)
    tags = []
    if mitre:
        tactic = mitre.get("tactic", "")
        tk = MITRE_TACTIC_KEYWORDS.get(tactic)
        if tk:
            tags.append(tk)
        if mitre.get("technique_id"):
            tags.append("attack." + mitre["technique_id"].lower().replace(".", ""))
    if not tags:
        tags = ["attack"]
    fields_yaml = "\n".join(f"    - {f}" for f in fields) if fields else "    - agent_name"
    tags_yaml = "\n".join(f"    - {t}" for t in tags)
    if kws:
        kw_lines = "".join(f'            - "{k}"\n' for k in kws)
    else:
        kw_lines = '            - "alert"\n'
    return f"""title: {title}
id: {rid}
status: experimental
description: Auto-generated rule for {title} derived from labeled SOC alert data
level: 6
logsource:
    product: wazuh
detection:
    selection_keywords:
        keywords:
{kw_lines}    condition: selection_keywords
fields:
{fields_yaml}
tags:
{tags_yaml}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", default="backend/sigma_rules")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing rule files")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        alerts = db.query(Alert).all()
    finally:
        db.close()

    if not alerts:
        print("No alerts in DB. Run: python -m scripts.seed_data --count 100")
        return

    groups = {}
    for a in alerts:
        title = a.sigma_title or "Unknown Alert"
        groups.setdefault(title, []).append(a)

    out_dir = Path(args.rules_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    used_ids = set()
    written = 0
    for title, members in groups.items():
        raw_texts = [a.raw_log or "" for a in members]
        sig_id = KNOWN_TITLE_TO_ID.get(title, "")
        mitre = MAP.get(sig_id, {})
        yaml_text = generate(title, raw_texts, mitre, used_ids)

        filename = _snake(title) + ".yml"
        dest = out_dir / filename
        if dest.exists() and not args.overwrite:
            print(f"SKIP  {filename} (exists, use --overwrite)")
            continue
        dest.write_text(yaml_text, encoding="utf-8")
        print(f"WROTE {filename}")
        written += 1

    print(f"\nGenerated {written} new Sigma rule(s) in {out_dir}")


if __name__ == "__main__":
    main()
