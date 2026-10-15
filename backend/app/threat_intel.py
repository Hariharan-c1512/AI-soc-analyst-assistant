"""Threat Intelligence module — enriches alerts with external threat data.

Uses VirusTotal, AbuseIPDB, and local threat feeds to provide context
about malicious IPs, domains, and file hashes.
"""
import logging
from typing import Optional
from dataclasses import dataclass

import httpx

from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Result from threat intelligence lookup."""
    ip: str
    is_malicious: bool
    threat_score: float
    country: str
    ISP: str
    reports: int
    malware_samples: int
    source: str
    details: str


class ThreatIntelligence:
    """Aggregates threat intel from multiple sources."""

    def __init__(self):
        self.vt_api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
        self._cache: dict[str, ThreatIntelResult] = {}

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Look up an IP address across threat intel sources."""
        if ip in self._cache:
            return self._cache[ip]

        # Try AbuseIPDB first (more reliable for IPs)
        result = self._abuseipdb_lookup(ip)
        if result:
            self._cache[ip] = result
            return result

        # Fallback to VirusTotal
        result = self._virustotal_lookup(ip)
        if result:
            self._cache[ip] = result
            return result

        # Return unknown
        return ThreatIntelResult(
            ip=ip,
            is_malicious=False,
            threat_score=0.0,
            country="Unknown",
            ISP="Unknown",
            reports=0,
            malware_samples=0,
            source="local",
            details="No threat intelligence data available"
        )

    def _abuseipdb_lookup(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query AbuseIPDB API."""
        if not self.abuseipdb_key:
            return None

        try:
            r = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                return ThreatIntelResult(
                    ip=ip,
                    is_malicious=data.get("abuseConfidenceScore", 0) > 50,
                    threat_score=float(data.get("abuseConfidenceScore", 0)) / 100,
                    country=data.get("countryCode", "Unknown"),
                    ISP=data.get("isp", "Unknown"),
                    reports=data.get("totalReports", 0),
                    malware_samples=0,
                    source="AbuseIPDB",
                    details=f"Confidence: {data.get('abuseConfidenceScore', 0)}%, Reports: {data.get('totalReports', 0)}"
                )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed: %s", e)
        return None

    def _virustotal_lookup(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query VirusTotal API."""
        if not self.vt_api_key:
            return None

        try:
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_api_key},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1

                return ThreatIntelResult(
                    ip=ip,
                    is_malicious=malicious > 3,
                    threat_score=malicious / total,
                    country=data.get("country", "Unknown"),
                    ISP=data.get("as_owner", "Unknown"),
                    reports=malicious,
                    malware_samples=stats.get("malicious", 0),
                    source="VirusTotal",
                    details=f"Detections: {malicious}/{total}, ASN: {data.get('as_owner', 'Unknown')}"
                )
        except Exception as e:
            logger.warning("VirusTotal lookup failed: %s", e)
        return None

    def enrich_alert(self, alert: dict) -> dict:
        """Add threat intel data to an alert."""
        # Extract IPs from alert
        raw_log = alert.get("raw_log", "")
        source_ip = ""

        # Try to extract source IP from raw log
        if "src" in raw_log:
            import re
            ip_match = re.search(r'"src":\s*"(\d+\.\d+\.\d+\.\d+)"', raw_log)
            if ip_match:
                source_ip = ip_match.group(1)

        if not source_ip:
            source_ip = alert.get("agent_ip", "")

        if source_ip and source_ip not in ("127.0.0.1", "localhost", ""):
            ti = self.lookup_ip(source_ip)
            alert["threat_intel"] = {
                "ip": ti.ip,
                "is_malicious": ti.is_malicious,
                "threat_score": ti.threat_score,
                "country": ti.country,
                "isp": ti.ISP,
                "reports": ti.reports,
                "source": ti.source,
                "details": ti.details,
            }
        else:
            alert["threat_intel"] = None

        return alert


_threat_intel: Optional[ThreatIntelligence] = None


def get_threat_intel() -> ThreatIntelligence:
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel
