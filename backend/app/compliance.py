"""Compliance Reports module — generates compliance reports for various standards.

Supports GDPR, HIPAA, SOC 2, and PCI DSS compliance reporting.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ComplianceReport:
    """Compliance report data."""
    standard: str
    report_date: str
    summary: dict
    findings: list[dict]
    recommendations: list[dict]
    score: float
    status: str  # compliant, non_compliant, partial


class ComplianceEngine:
    """Generates compliance reports based on security alerts and controls."""

    def __init__(self):
        self.standards = {
            "GDPR": self._gdpr_report,
            "HIPAA": self._hipaa_report,
            "SOC2": self._soc2_report,
            "PCI_DSS": self._pci_dss_report,
        }

    def generate_report(self, standard: str, alerts: list[dict], stats: dict) -> ComplianceReport:
        """Generate a compliance report for the specified standard."""
        if standard not in self.standards:
            raise ValueError(f"Unknown standard: {standard}")

        return self.standards[standard](alerts, stats)

    def _gdpr_report(self, alerts: list[dict], stats: dict) -> ComplianceReport:
        """Generate GDPR compliance report."""
        # Count data-related alerts
        data_breach_alerts = [a for a in alerts if "exfiltration" in (a.get("description", "").lower() or "")]
        unauthorized_access = [a for a in alerts if "brute" in (a.get("description", "").lower() or "")]

        findings = []
        if len(data_breach_alerts) > 0:
            findings.append({
                "control": "Data Breach Detection",
                "status": "non_compliant",
                "evidence": f"{len(data_breach_alerts)} potential data breach alerts detected",
                "risk": "high",
            })
        else:
            findings.append({
                "control": "Data Breach Detection",
                "status": "compliant",
                "evidence": "No data breach alerts detected",
                "risk": "low",
            })

        if len(unauthorized_access) > 0:
            findings.append({
                "control": "Access Control Monitoring",
                "status": "partial",
                "evidence": f"{len(unauthorized_access)} unauthorized access attempts detected",
                "risk": "medium",
            })
        else:
            findings.append({
                "control": "Access Control Monitoring",
                "status": "compliant",
                "evidence": "Access controls properly monitored",
                "risk": "low",
            })

        recommendations = [
            {"control": "Article 32", "recommendation": "Implement encryption for data at rest and in transit", "priority": "high"},
            {"control": "Article 33", "recommendation": "Establish 72-hour breach notification process", "priority": "high"},
            {"control": "Article 25", "recommendation": "Implement data protection by design and default", "priority": "medium"},
            {"control": "Article 17", "recommendation": "Implement right to erasure procedures", "priority": "medium"},
        ]

        score = self._calculate_score(findings)

        return ComplianceReport(
            standard="GDPR",
            report_date=datetime.now(timezone.utc).isoformat(),
            summary={
                "total_findings": len(findings),
                "compliant": sum(1 for f in findings if f["status"] == "compliant"),
                "non_compliant": sum(1 for f in findings if f["status"] == "non_compliant"),
                "partial": sum(1 for f in findings if f["status"] == "partial"),
            },
            findings=findings,
            recommendations=recommendations,
            score=score,
            status="compliant" if score >= 80 else "non_compliant",
        )

    def _hipaa_report(self, alerts: list[dict], stats: dict) -> ComplianceReport:
        """Generate HIPAA compliance report."""
        phi_access_alerts = [a for a in alerts if a.get("mitre_technique_id") in ("T1110", "T1078")]

        findings = []
        if len(phi_access_alerts) > 10:
            findings.append({
                "control": "Access Controls (§164.312(a))",
                "status": "non_compliant",
                "evidence": f"{len(phi_access_alerts)} unauthorized access attempts to PHI systems",
                "risk": "high",
            })
        else:
            findings.append({
                "control": "Access Controls (§164.312(a))",
                "status": "compliant",
                "evidence": "Access attempts within acceptable threshold",
                "risk": "low",
            })

        findings.append({
            "control": "Audit Controls (§164.312(b))",
            "status": "compliant" if stats.get("total_alerts", 0) > 0 else "non_compliant",
            "evidence": f"Audit logging active: {stats.get('total_alerts', 0)} events recorded",
            "risk": "low",
        })

        recommendations = [
            {"control": "§164.312(a)(1)", "recommendation": "Implement unique user identification", "priority": "high"},
            {"control": "§164.312(a)(2)(iii)", "recommendation": "Implement automatic logoff", "priority": "medium"},
            {"control": "§164.312(d)", "recommendation": "Implement person authentication mechanisms", "priority": "high"},
            {"control": "§164.312(e)(1)", "recommendation": "Implement transmission security", "priority": "medium"},
        ]

        score = self._calculate_score(findings)

        return ComplianceReport(
            standard="HIPAA",
            report_date=datetime.now(timezone.utc).isoformat(),
            summary={
                "total_findings": len(findings),
                "compliant": sum(1 for f in findings if f["status"] == "compliant"),
                "non_compliant": sum(1 for f in findings if f["status"] == "non_compliant"),
                "partial": sum(1 for f in findings if f["status"] == "partial"),
            },
            findings=findings,
            recommendations=recommendations,
            score=score,
            status="compliant" if score >= 80 else "non_compliant",
        )

    def _soc2_report(self, alerts: list[dict], stats: dict) -> ComplianceReport:
        """Generate SOC 2 compliance report."""
        critical_alerts = [a for a in alerts if a.get("ml_severity") == "critical"]

        findings = []
        findings.append({
            "control": "Security Monitoring (CC7.1)",
            "status": "compliant",
            "evidence": f"Security monitoring active: {stats.get('total_alerts', 0)} alerts processed",
            "risk": "low",
        })

        if len(critical_alerts) > 5:
            findings.append({
                "control": "Incident Response (CC7.3)",
                "status": "partial",
                "evidence": f"{len(critical_alerts)} critical alerts require investigation",
                "risk": "medium",
            })
        else:
            findings.append({
                "control": "Incident Response (CC7.3)",
                "status": "compliant",
                "evidence": "Critical alerts within manageable threshold",
                "risk": "low",
            })

        recommendations = [
            {"control": "CC7.1", "recommendation": "Maintain continuous monitoring with automated alerting", "priority": "high"},
            {"control": "CC7.2", "recommendation": "Establish incident response procedures and escalation paths", "priority": "high"},
            {"control": "CC7.3", "recommendation": "Implement automated containment actions", "priority": "medium"},
            {"control": "CC6.1", "recommendation": "Deploy network segmentation and access controls", "priority": "medium"},
        ]

        score = self._calculate_score(findings)

        return ComplianceReport(
            standard="SOC 2",
            report_date=datetime.now(timezone.utc).isoformat(),
            summary={
                "total_findings": len(findings),
                "compliant": sum(1 for f in findings if f["status"] == "compliant"),
                "non_compliant": sum(1 for f in findings if f["status"] == "non_compliant"),
                "partial": sum(1 for f in findings if f["status"] == "partial"),
            },
            findings=findings,
            recommendations=recommendations,
            score=score,
            status="compliant" if score >= 80 else "non_compliant",
        )

    def _pci_dss_report(self, alerts: list[dict], stats: dict) -> ComplianceReport:
        """Generate PCI DSS compliance report."""
        findings = []
        findings.append({
            "control": "Requirement 10: Track and monitor access",
            "status": "compliant",
            "evidence": f"Access logging active: {stats.get('total_alerts', 0)} events tracked",
            "risk": "low",
        })

        high_risk_alerts = [a for a in alerts if a.get("ml_severity") in ("critical", "high")]
        if len(high_risk_alerts) > 0:
            findings.append({
                "control": "Requirement 11: Regularly test security systems",
                "status": "partial",
                "evidence": f"{len(high_risk_alerts)} high-risk alerts indicate potential vulnerabilities",
                "risk": "medium",
            })

        recommendations = [
            {"control": "Req 1.1", "recommendation": "Maintain firewall configuration standards", "priority": "high"},
            {"control": "Req 6.5", "recommendation": "Address common coding vulnerabilities", "priority": "high"},
            {"control": "Req 8.1", "recommendation": "Assign unique ID to each person with access", "priority": "medium"},
            {"control": "Req 10.2", "recommendation": "Implement automated audit trails", "priority": "medium"},
        ]

        score = self._calculate_score(findings)

        return ComplianceReport(
            standard="PCI DSS",
            report_date=datetime.now(timezone.utc).isoformat(),
            summary={
                "total_findings": len(findings),
                "compliant": sum(1 for f in findings if f["status"] == "compliant"),
                "non_compliant": sum(1 for f in findings if f["status"] == "non_compliant"),
                "partial": sum(1 for f in findings if f["status"] == "partial"),
            },
            findings=findings,
            recommendations=recommendations,
            score=score,
            status="compliant" if score >= 80 else "non_compliant",
        )

    def _calculate_score(self, findings: list[dict]) -> float:
        """Calculate compliance score based on findings."""
        if not findings:
            return 100.0

        weights = {"compliant": 1.0, "partial": 0.5, "non_compliant": 0.0}
        total = sum(weights.get(f["status"], 0) for f in findings)
        return round((total / len(findings)) * 100, 1)


_compliance: Optional[ComplianceEngine] = None


def get_compliance() -> ComplianceEngine:
    global _compliance
    if _compliance is None:
        _compliance = ComplianceEngine()
    return _compliance
