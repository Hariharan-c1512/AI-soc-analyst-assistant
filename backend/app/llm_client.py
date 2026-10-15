"""LLM client — connects to a local Ollama server, with an offline fallback
that generates template-based analysis so the pipeline always produces output.
"""
import json
import logging
import time
from typing import Optional

import httpx

from .config import settings

logger = logging.getLogger(__name__)

REMEDIATION_BANK = {
    "T1204.002": [
        "Isolate the affected host from the network immediately",
        "Quarantine the detected malicious file and record its hash",
        "Verify whether the file executed — check process tree and scheduled tasks",
        "Run a full AV scan of the endpoint with updated signatures",
    ],
    "T1486": [
        "Disconnect the affected host(s) from the network",
        "Identify the encryption scope — list affected file extensions and volume",
        "Restore files from the latest clean backup",
        "Contain lateral movement: block SMB/management ports from affected hosts",
    ],
    "T1071.001": [
        "Block the destination IP at the firewall and proxy",
        "Isolate the host and capture a memory dump of the process",
        "Review the process tree for the origin of the C2 beacon",
        "Search network logs for other hosts contacting the same IP",
    ],
    "T1059.001": [
        "Review the full PowerShell command line for malicious intent",
        "Enable and inspect PowerShell script block logging and AMSI",
        "Check for persistence via scheduled tasks, Run keys, WMI",
        "Reset the affected user account credentials",
    ],
    "T1110": [
        "Block the source IP at the perimeter firewall",
        "Enforce account lockout policies and MFA on exposed services",
        "Review authentication logs for successful logins from the source",
        "Move SSH to non-default port / key-based auth only",
    ],
    "T1505.003": [
        "Remove the uploaded web shell file immediately",
        "Review web server access logs for the upload origin",
        "Scan the web root for additional webshells",
        "Harden upload directories: disable script execution",
    ],
    "T1190": [
        "Patch the vulnerable public-facing application",
        "Add WAF rules blocking SQL injection patterns",
        "Review application logs for successful injection attempts",
        "Validate all user input server-side",
    ],
    "T1046": [
        "Identify the scanning source and block it",
        "Close unnecessary open ports on scanned hosts",
        "Implement egress filtering to limit outbound scanning",
        "Review firewall rules for exposure",
    ],
    "T1091": [
        "Restrict USB storage via GPO / endpoint policy",
        "Scan removable media on connection",
        "Log and review USB insertions",
        "Deploy endpoint DLP controls",
    ],
    "T1070.001": [
        "Verify file integrity baseline and re-establish trusted snapshot",
        "Determine whether the change was expected (patch/update)",
        "Check for unauthorized access that preceded the change",
        "Restore the file from backup if compromised",
    ],
    "T1068": [
        "Audit sudoers configuration and remove risky rules",
        "Review /var/log/auth.log for repeated escalation attempts",
        "Apply the latest kernel/OS security patches",
        "Require password (not NOPASSWD) for privileged commands",
    ],
    "T1078": [
        "Review account permission changes and revert unauthorized grants",
        "Enforce least-privilege across the environment",
        "Enable auditing on directory service changes",
        "Reset credentials of affected accounts",
    ],
}

EXPLANATION_BANK = {
    "T1204.002": "Malicious File execution occurs when a user or automated process opens a file that contains malware. In SOC terms, this detection means a sample was found by AV/ClamAV on disk — the risk depends on whether the file executed.",
    "T1486": "Ransomware encrypts files to demand payment. Detecting bulk file modification with unusual extensions is a strong indicator of active encryption.",
    "T1071.001": "Attackers tunnel command-and-control traffic inside normal protocols like HTTPS to evade detection. A process calling out to a known-bad IP over 443 is a classic beaconing signature.",
    "T1059.001": "PowerShell is a dual-use tool: administrators automate tasks, attackers execute in-memory payloads. Encoded commands are a strong malicious indicator.",
    "T1110": "Brute force attempts repeatedly guess credentials. Many failures from one source against a service suggests credential stuffing or password spraying.",
    "T1505.003": "A web shell gives attackers persistent remote access through the web server, often used to pivot into the internal network.",
    "T1190": "SQL injection exploits weak input validation to query the database directly. Successful exploitation can exfiltrate data or enable authentication bypass.",
    "T1046": "Port scanning discovers exposed services and is typically the first step in network reconnaissance.",
    "T1091": "USB devices can introduce malware or exfiltrate data. Connection events help track removable media usage.",
    "T1070.001": "File integrity monitoring detects unauthorized changes to critical files, which may indicate tampering by an attacker.",
    "T1068": "Privilege escalation exploits gain higher permissions than authorized. Sudo misuse is a common Linux vector.",
    "T1078": "Valid accounts are the most-used technique — attackers use legitimate credentials to move laterally and persist.",
}


class LLMClient:
    def __init__(self, mode: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None):
        self.mode = (mode or settings.LLM_MODE).lower()
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.model = model or settings.OLLAMA_MODEL

    @property
    def is_ollama(self) -> bool:
        return self.mode == "ollama"

    def available(self) -> bool:
        if not self.is_ollama:
            return False
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: str = "", temperature: float = 0.4) -> str:
        if self.is_ollama:
            try:
                resp = httpx.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "system": system,
                        "stream": False,
                        "temperature": temperature,
                        "options": {"num_predict": 512},
                    },
                    timeout=120,
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "").strip()
            except Exception as e:  # pragma: no cover
                logger.warning("Ollama request failed (%s) — using offline fallback", e)
        return self._offline(prompt)

    def _offline(self, prompt: str) -> str:
        """Template-based answer for when no LLM is running."""
        data = {}
        try:
            payload = json.loads(prompt)
            data = payload.get("alert", {})
        except Exception:
            pass

        tid = (data.get("mitre_technique_id") or "").upper()
        technique = data.get("mitre_technique") or "Unknown"
        summary = data.get("ai_summary") or data.get("description") or "No description"

        rem = REMEDIATION_BANK.get(tid, ["Confirm the alert scope, isolate the host, review logs, and escalate if needed"])
        exp = EXPLANATION_BANK.get(tid, "This alert matches an attack pattern worth investigating.")

        steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(rem))
        return (
            f"[Offline analysis mode]\n\n"
            f"Incident Summary:\n{summary}\n\n"
            f"Technique ({tid or 'N/A'}): {technique}\n{exp}\n\n"
            f"Recommended Remediation Steps:\n{steps}"
        )

    def analyze_alert(self, alert: dict, rag_context: Optional[list] = None) -> dict:
        """Generate full analysis dict {summary, technique, remediation, rag_sources, model, ms}."""
        t0 = time.monotonic()
        tid = (alert.get("mitre_technique_id") or "").upper()
        technique = alert.get("mitre_technique") or "Unknown technique"
        description = alert.get("description") or "Security alert"
        agent = alert.get("agent_name") or "unknown host"
        level = alert.get("wazuh_level") or 0

        # Build a summary line
        summary = (
            f"{description} on {agent} (severity {alert.get('ml_severity')}, Wazuh level {level}). "
            f"Detected via rule {alert.get('wazuh_rule_id')} and matched Sigma rule {alert.get('sigma_rule_id')}."
        )

        rag_sources = []
        context = ""
        if rag_context:
            rag_sources = [c.get("alert_ref") for c in rag_context[: settings.RAG_TOP_K]]
            context = "\n".join(
                f"- {c.get('alert_ref')} ({c.get('similarity', 0):.2f}): {c.get('description')}" for c in rag_context[: settings.RAG_TOP_K]
            )

        # Prompt embeds alert JSON so offline mode can parse it too
        prompt = json.dumps(
            {
                "task": "analyze_alert",
                "alert": {
                    "description": description,
                    "agent_name": agent,
                    "ml_severity": alert.get("ml_severity"),
                    "wazuh_level": level,
                    "mitre_technique": technique,
                    "mitre_technique_id": tid,
                    "ai_summary": summary,
                },
                "rag_context": context,
            },
            ensure_ascii=False,
        )

        system = (
            "You are a SOC analyst assistant. Given a security alert and related "
            "past incidents, produce a concise incident summary, explain the attack "
            "technique, and list actionable remediation steps."
        )
        output = self.generate(prompt, system=system)
        ms = int((time.monotonic() - t0) * 1000)
        return {
            "summary": summary,
            "technique": output if self.is_ollama else "",
            "remediation": output,
            "rag_sources": rag_sources,
            "model": f"{self.model} (ollama)" if self.is_ollama else "offline-template",
            "generation_ms": ms,
        }


_llm: Optional[LLMClient] = None


def get_llm() -> LLMClient:
    global _llm
    if _llm is None:
        _llm = LLMClient()
    return _llm
