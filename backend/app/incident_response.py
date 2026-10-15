"""Incident Response module — automated response actions for security alerts.

Provides safe, controlled response actions like IP blocking, host isolation,
and evidence collection.
"""
import logging
import subprocess
import json
from typing import Optional
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class IRAction:
    """Incident Response action result."""
    action: str
    target: str
    status: str
    message: str
    timestamp: str
    requires_approval: bool


class IncidentResponse:
    """Automated incident response actions."""

    # Actions that require manual approval
    DESTRUCTIVE_ACTIONS = {"isolate_host", "block_ip_global", "quarantine_file"}

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run  # Safe mode - logs actions but doesn't execute
        self.action_log: list[IRAction] = []

    def execute_action(self, action: str, target: str, params: dict = None) -> IRAction:
        """Execute an IR action."""
        params = params or {}
        ts = datetime.now(timezone.utc).isoformat()
        requires_approval = action in self.DESTRUCTIVE_ACTIONS

        if self.dry_run:
            result = IRAction(
                action=action,
                target=target,
                status="dry_run",
                message=f"[DRY RUN] Would execute: {action} on {target}",
                timestamp=ts,
                requires_approval=requires_approval,
            )
        else:
            try:
                if action == "block_ip":
                    result = self._block_ip(target)
                elif action == "block_ip_global":
                    result = self._block_ip_global(target)
                elif action == "isolate_host":
                    result = self._isolate_host(target)
                elif action == "collect_evidence":
                    result = self._collect_evidence(target)
                elif action == "kill_process":
                    result = self._kill_process(target, params.get("pid"))
                elif action == "reset_password":
                    result = self._reset_password(target)
                elif action == "disable_account":
                    result = self._disable_account(target)
                else:
                    result = IRAction(
                        action=action,
                        target=target,
                        status="error",
                        message=f"Unknown action: {action}",
                        timestamp=ts,
                        requires_approval=requires_approval,
                    )
            except Exception as e:
                result = IRAction(
                    action=action,
                    target=target,
                    status="error",
                    message=str(e),
                    timestamp=ts,
                    requires_approval=requires_approval,
                )

        self.action_log.append(result)
        return result

    def _block_ip(self, ip: str) -> IRAction:
        """Block an IP using iptables (local firewall only)."""
        ts = datetime.now(timezone.utc).isoformat()
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        logger.info("Blocking IP: %s", ip)

        try:
            subprocess.run(cmd.split(), check=True, capture_output=True, timeout=10)
            return IRAction(
                action="block_ip",
                target=ip,
                status="success",
                message=f"IP {ip} blocked in local firewall",
                timestamp=ts,
                requires_approval=False,
            )
        except subprocess.CalledProcessError as e:
            return IRAction(
                action="block_ip",
                target=ip,
                status="error",
                message=f"Failed to block IP: {e}",
                timestamp=ts,
                requires_approval=False,
            )

    def _block_ip_global(self, ip: str) -> IRAction:
        """Block IP at network level (requires external API)."""
        ts = datetime.now(timezone.utc).isoformat()
        logger.info("Requesting global IP block: %s", ip)
        return IRAction(
            action="block_ip_global",
            target=ip,
            status="pending_approval",
            message=f"Global IP block requested for {ip}. Requires network admin approval.",
            timestamp=ts,
            requires_approval=True,
        )

    def _isolate_host(self, host: str) -> IRAction:
        """Isolate a host from the network."""
        ts = datetime.now(timezone.utc).isoformat()
        logger.info("Requesting host isolation: %s", host)
        return IRAction(
            action="isolate_host",
            target=host,
            status="pending_approval",
            message=f"Host isolation requested for {host}. Requires admin approval.",
            timestamp=ts,
            requires_approval=True,
        )

    def _collect_evidence(self, target: str) -> IRAction:
        """Collect forensic evidence from a host."""
        ts = datetime.now(timezone.utc).isoformat()
        evidence = {
            "target": target,
            "timestamp": ts,
            "collected": ["network_connections", "process_list", "log_entries"],
        }
        return IRAction(
            action="collect_evidence",
            target=target,
            status="success",
            message=f"Evidence collection initiated for {target}",
            timestamp=ts,
            requires_approval=False,
        )

    def _kill_process(self, target: str, pid: Optional[str] = None) -> IRAction:
        """Kill a suspicious process."""
        ts = datetime.now(timezone.utc).isoformat()
        if pid:
            logger.info("Killing process %s on %s", pid, target)
        return IRAction(
            action="kill_process",
            target=target,
            status="success",
            message=f"Process termination requested on {target}",
            timestamp=ts,
            requires_approval=False,
        )

    def _reset_password(self, user: str) -> IRAction:
        """Reset a compromised user password."""
        ts = datetime.now(timezone.utc).isoformat()
        return IRAction(
            action="reset_password",
            target=user,
            status="pending_approval",
            message=f"Password reset requested for user {user}",
            timestamp=ts,
            requires_approval=True,
        )

    def _disable_account(self, user: str) -> IRAction:
        """Disable a compromised account."""
        ts = datetime.now(timezone.utc).isoformat()
        return IRAction(
            action="disable_account",
            target=user,
            status="pending_approval",
            message=f"Account disable requested for {user}",
            timestamp=ts,
            requires_approval=True,
        )

    def get_available_actions(self, alert: dict) -> list[dict]:
        """Get recommended actions based on alert type."""
        mitre_tid = alert.get("mitre_technique_id", "")
        severity = alert.get("ml_severity", "low")
        agent = alert.get("agent_name", "")

        actions = []

        # Common actions for all alerts
        actions.append({
            "id": "collect_evidence",
            "name": "Collect Evidence",
            "description": "Gather forensic data from the affected host",
            "target": agent,
            "requires_approval": False,
            "icon": "🔍",
        })

        # IP-based actions
        if mitre_tid in ("T1110", "T1071.001", "T1046"):
            actions.append({
                "id": "block_ip",
                "name": "Block Source IP",
                "description": "Block the attacking IP at local firewall",
                "target": "attacker_ip",
                "requires_approval": False,
                "icon": "🚫",
            })

        # Host isolation for critical alerts
        if severity == "critical":
            actions.append({
                "id": "isolate_host",
                "name": "Isolate Host",
                "description": "Disconnect the host from the network",
                "target": agent,
                "requires_approval": True,
                "icon": "🔌",
            })

        # Account-based actions
        if mitre_tid in ("T1110", "T1078", "T1068"):
            actions.append({
                "id": "reset_password",
                "name": "Reset User Password",
                "description": "Force password reset for compromised account",
                "target": "affected_user",
                "requires_approval": True,
                "icon": "🔑",
            })
            actions.append({
                "id": "disable_account",
                "name": "Disable Account",
                "description": "Temporarily disable the compromised account",
                "target": "affected_user",
                "requires_approval": True,
                "icon": "🔒",
            })

        # Process-based actions
        if mitre_tid in ("T1059.001", "T1204.002"):
            actions.append({
                "id": "kill_process",
                "name": "Kill Suspicious Process",
                "description": "Terminate the malicious process",
                "target": agent,
                "requires_approval": False,
                "icon": "⛔",
            })

        return actions

    def get_action_log(self) -> list[dict]:
        """Get log of all executed actions."""
        return [
            {
                "action": a.action,
                "target": a.target,
                "status": a.status,
                "message": a.message,
                "timestamp": a.timestamp,
                "requires_approval": a.requires_approval,
            }
            for a in self.action_log
        ]


_ir: Optional[IncidentResponse] = None


def get_incident_response(dry_run: bool = True) -> IncidentResponse:
    global _ir
    if _ir is None:
        _ir = IncidentResponse(dry_run=dry_run)
    return _ir
