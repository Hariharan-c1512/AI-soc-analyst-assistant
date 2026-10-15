"""Mock alert generator — produces realistic Wazuh-style alerts with no external deps.

Used when INGESTION_MODE=mock so the full pipeline can run without a live Wazuh
deployment. Each template maps to realistic rule IDs, Sigma rules, and MITRE ATT&CK.
"""
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

AGENTS = [
    {"name": "win-ep-01", "ip": "10.0.1.11", "os": "Windows 10"},
    {"name": "win-ep-02", "ip": "10.0.1.12", "os": "Windows 10"},
    {"name": "win-wk-05", "ip": "10.0.2.25", "os": "Windows 10"},
    {"name": "win-wk-12", "ip": "10.0.2.32", "os": "Windows 10"},
    {"name": "win-srv-02", "ip": "10.0.3.42", "os": "Windows Server 2019"},
    {"name": "srv-web01", "ip": "10.0.4.21", "os": "Ubuntu 22.04"},
    {"name": "srv-web02", "ip": "10.0.4.45", "os": "Ubuntu 22.04"},
    {"name": "srv-db01", "ip": "10.0.5.10", "os": "Ubuntu 20.04"},
    {"name": "srv-mail01", "ip": "10.0.6.14", "os": "Debian 11"},
    {"name": "fw-edge01", "ip": "192.168.1.1", "os": "RouterOS"},
]

MALICIOUS_IPS = ["185.130.5.77", "91.218.114.31", "45.155.205.233", "193.169.255.133", "162.244.80.56"]
LEGIT_IPS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "13.107.42.14"]


@dataclass
class AlertTemplate:
    rule_id: int
    level: int
    description: str
    sigma_rule_id: str
    sigma_title: str
    mitre_tactic: str
    mitre_tactic_id: str
    mitre_technique: str
    mitre_technique_id: str
    kill_chain: str
    raw_log_template: str = ""
    os_filter: str = "any"  # windows | linux | any
    base_confidence: float = 0.75


TEMPLATES: list[AlertTemplate] = [
    AlertTemplate(
        rule_id=87104, level=12, description="ClamAV: Malware detected",
        sigma_rule_id="MAL-001", sigma_title="Malware Detected by AntiVirus",
        mitre_tactic="Execution", mitre_tactic_id="TA0002",
        mitre_technique="User Execution: Malicious File", mitre_technique_id="T1204.002",
        kill_chain="Delivery",
        raw_log_template='{{"clamav": "Win.Test.EICAR_HDB-1 FOUND", "file": "{path}", "agent": "{agent}"}}',
        os_filter="windows", base_confidence=0.91,
    ),
    AlertTemplate(
        rule_id=87109, level=15, description="Ransomware behavior detected",
        sigma_rule_id="RAN-001", sigma_title="Ransomware File Encryption Pattern",
        mitre_tactic="Impact", mitre_tactic_id="TA0040",
        mitre_technique="Data Encrypted for Impact", mitre_technique_id="T1486",
        kill_chain="Actions on Objectives",
        raw_log_template='{{"behavior": "bulk file modification", "ext": ".locked", "count": {n}, "dir": "{path}"}}',
        os_filter="windows", base_confidence=0.94,
    ),
    AlertTemplate(
        rule_id=87112, level=14, description="Outbound connection to known malicious IP",
        sigma_rule_id="CMD-014", sigma_title="Suspicious Outbound Connection to C2 IP",
        mitre_tactic="Command and Control", mitre_tactic_id="TA0011",
        mitre_technique="Application Layer Protocol: Web Protocols", mitre_technique_id="T1071.001",
        kill_chain="Command and Control",
        raw_log_template='{{"src_ip": "{src}", "dst_ip": "{dst}", "dst_port": 443, "proto": "tcp", "bytes": {b}, "process": "{proc}"}}',
        os_filter="any", base_confidence=0.89,
    ),
    AlertTemplate(
        rule_id=87103, level=10, description="Suspicious PowerShell command",
        sigma_rule_id="PS-001", sigma_title="Suspicious PowerShell Command Line",
        mitre_tactic="Execution", mitre_tactic_id="TA0002",
        mitre_technique="Command and Scripting Interpreter: PowerShell", mitre_technique_id="T1059.001",
        kill_chain="Execution",
        raw_log_template='{{"ps_command": "powershell -enc {b64}", "user": "{user}", "host": "{agent}"}}',
        os_filter="windows", base_confidence=0.84,
    ),
    AlertTemplate(
        rule_id=5753, level=10, description="Multiple failed SSH login attempts (brute force)",
        sigma_rule_id="BRUTE-002", sigma_title="SSH Brute Force",
        mitre_tactic="Credential Access", mitre_tactic_id="TA0006",
        mitre_technique="Brute Force", mitre_technique_id="T1110",
        kill_chain="Initial Access",
        raw_log_template='{{"attempts": {n}, "src": "{src}", "user": "{user}", "service": "sshd"}}',
        os_filter="linux", base_confidence=0.82,
    ),
    AlertTemplate(
        rule_id=31151, level=9, description="Web shell upload attempt detected",
        sigma_rule_id="WEB-001", sigma_title="Web Shell Upload Attempt",
        mitre_tactic="Persistence", mitre_tactic_id="TA0003",
        mitre_technique="Server Software Component: Web Shell", mitre_technique_id="T1505.003",
        kill_chain="Installation",
        raw_log_template='{{"uri": "/uploads/shell.php", "src": "{src}", "status": 200, "size": {n}}}',
        os_filter="linux", base_confidence=0.86,
    ),
    AlertTemplate(
        rule_id=31153, level=8, description="SQL injection attempt detected",
        sigma_rule_id="WEB-002", sigma_title="SQL Injection Attempt",
        mitre_tactic="Initial Access", mitre_tactic_id="TA0001",
        mitre_technique="Exploit Public-Facing Application", mitre_technique_id="T1190",
        kill_chain="Delivery",
        raw_log_template='{{"uri": "/products?id={sql}", "src": "{src}", "method": "GET"}}',
        os_filter="linux", base_confidence=0.78,
    ),
    AlertTemplate(
        rule_id=5701, level=6, description="Network scan / port sweep detected",
        sigma_rule_id="SCAN-001", sigma_title="Network Port Scan",
        mitre_tactic="Discovery", mitre_tactic_id="TA0007",
        mitre_technique="Network Service Discovery", mitre_technique_id="T1046",
        kill_chain="Reconnaissance",
        raw_log_template='{{"proto": "tcp", "ports_scanned": {n}, "src": "{src}"}}',
        os_filter="any", base_confidence=0.65,
    ),
    AlertTemplate(
        rule_id=101000, level=4, description="USB storage device connected",
        sigma_rule_id="MEDIA-001", sigma_title="USB Device Connected",
        mitre_tactic="Initial Access", mitre_tactic_id="TA0001",
        mitre_technique="Replication Through Removable Media", mitre_technique_id="T1091",
        kill_chain="Delivery",
        raw_log_template='{{"usb": "USBSTOR\\\\DISK&VEN_SanDisk", "serial": "SN{n}", "host": "{agent}"}}',
        os_filter="windows", base_confidence=0.6,
    ),
    AlertTemplate(
        rule_id=5501, level=5, description="Critical file integrity change",
        sigma_rule_id="FIM-001", sigma_title="File Integrity Monitoring Change",
        mitre_tactic="Defense Evasion", mitre_tactic_id="TA0005",
        mitre_technique="Indicator Removal on Host: File Deletion", mitre_technique_id="T1070.001",
        kill_chain="Defense Evasion",
        raw_log_template='{{"file": "{path}", "change": "modified", "checksum": "md5:{md5}"}}',
        os_filter="any", base_confidence=0.62,
    ),
    AlertTemplate(
        rule_id=5901, level=9, description="Privilege escalation attempt (sudo misuse)",
        sigma_rule_id="PRIV-001", sigma_title="Sudo Privilege Escalation",
        mitre_tactic="Privilege Escalation", mitre_tactic_id="TA0004",
        mitre_technique="Exploitation for Privilege Escalation", mitre_technique_id="T1068",
        kill_chain="Exploitation",
        raw_log_template='{{"sudo": "user={user} command=/bin/su", "tty": "pts/0", "host": "{agent}"}}',
        os_filter="linux", base_confidence=0.8,
    ),
]

LEVEL_TO_SEVERITY = {15: 3, 14: 3, 12: 3, 13: 3, 10: 2, 9: 2, 8: 2, 6: 1, 5: 1, 4: 0}
SEVERITY_LABELS = ["low", "medium", "high", "critical"]


def _random_path(agent_os: str) -> str:
    if agent_os.startswith("Windows"):
        return random.choice([
            r"C:\Users\Public\Downloads", r"C:\Windows\Temp", r"C:\Users\user\Documents",
            r"C:\ProgramData", r"C:\Users\user\AppData\Local\Temp",
        ])
    return random.choice(["/tmp", "/var/tmp", "/home/user/.cache", "/dev/shm", "/opt"])


def _random_user() -> str:
    return random.choice(["user", "admin", "svc_web", "svc_db", "root", "jdoe", "backup"])


def _random_md5() -> str:
    return "".join(random.choices("0123456789abcdef", k=32))


def _os_matches(os_type: str, os_filter: str) -> bool:
    if os_filter == "any":
        return True
    t = os_type.lower()
    if os_filter == "windows":
        return "win" in t
    return any(k in t for k in ("ubuntu", "debian", "linux", "centos", "redhat", "suse"))


def build_mock_alert(index: int) -> dict:
    """Generate one realistic normalized alert."""
    tpl = random.choice(TEMPLATES)
    candidates = [a for a in AGENTS if _os_matches(a["os"], tpl.os_filter)]
    agent = random.choice(candidates)
    ts = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 3600))

    rnd = random.random()
    n = random.randint(1, 4000)
    src = random.choice(MALICIOUS_IPS if rnd < 0.6 else LEGIT_IPS)

    path = _random_path(agent["os"])
    user = _random_user()
    payload = tpl.raw_log_template.format(
        agent=agent["name"], path=path, n=n, src=src,
        dst=random.choice(MALICIOUS_IPS), b=random.randint(100, 9000),
        proc=random.choice(["/usr/bin/python3 -c '<b64>'", "powershell.exe -enc <b64>", "curl -s http://{dst}/a"]),
        b64="JABjAG0AZAAgAD0AIABpAGUANw", user=user,
        sql="1' OR '1'='1", md5=_random_md5(),
    )

    # Ground-truth severity from template (used for the synthetic ML dataset).
    true_sev = SEVERITY_LABELS[LEVEL_TO_SEVERITY[tpl.level]]
    # ML predictor should produce the same value for identical features (deterministic-ish).
    confidence = min(0.99, tpl.base_confidence + random.uniform(-0.05, 0.05))

    return {
        "alert_ref": f"AL-{19000 + index}",
        "timestamp": ts,
        "agent_name": agent["name"],
        "agent_ip": agent["ip"],
        "os_type": agent["os"],
        "source": "mock",
        "wazuh_rule_id": tpl.rule_id,
        "wazuh_level": tpl.level,
        "sigma_rule_id": tpl.sigma_rule_id,
        "sigma_title": tpl.sigma_title,
        "description": tpl.description,
        "raw_log": payload,
        "ml_severity": true_sev,
        "ml_confidence": round(confidence, 3),
        "mitre_tactic": tpl.mitre_tactic,
        "mitre_tactic_id": tpl.mitre_tactic_id,
        "mitre_technique": tpl.mitre_technique,
        "mitre_technique_id": tpl.mitre_technique_id,
        "kill_chain_phase": tpl.kill_chain,
    }
