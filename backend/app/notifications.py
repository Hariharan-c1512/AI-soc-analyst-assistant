"""Notification system — sends alerts via Email, Telegram, and Desktop.

Supports multiple notification channels for critical alerts.
"""
import logging
import smtplib
import subprocess
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from dataclasses import dataclass

import httpx

from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Notification configuration."""
    email_enabled: bool = False
    email_smtp_host: str = "smtp.gmail.com"
    email_smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: list[str] = None

    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    min_severity: str = "critical"  # Only notify for this severity and above
    desktop_enabled: bool = False

    def __post_init__(self):
        if self.email_recipients is None:
            self.email_recipients = []


class NotificationService:
    """Sends notifications across multiple channels."""

    SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or self._load_config()

    def _load_config(self) -> NotificationConfig:
        """Load config from environment."""
        def _to_bool(val) -> bool:
            if isinstance(val, bool):
                return val
            return str(val).lower() == "true"

        return NotificationConfig(
            email_enabled=_to_bool(getattr(settings, "EMAIL_ENABLED", "false")),
            email_smtp_host=getattr(settings, "EMAIL_SMTP_HOST", "smtp.gmail.com"),
            email_smtp_port=int(getattr(settings, "EMAIL_SMTP_PORT", "587")),
            email_username=getattr(settings, "EMAIL_USERNAME", ""),
            email_password=getattr(settings, "EMAIL_PASSWORD", ""),
            email_recipients=getattr(settings, "EMAIL_RECIPIENTS", "").split(","),
            telegram_enabled=_to_bool(getattr(settings, "TELEGRAM_ENABLED", "false")),
            telegram_bot_token=getattr(settings, "TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=getattr(settings, "TELEGRAM_CHAT_ID", ""),
            min_severity=getattr(settings, "NOTIFICATION_MIN_SEVERITY", "critical"),
            desktop_enabled=_to_bool(getattr(settings, "DESKTOP_NOTIFICATIONS", "false")),
        )

    def should_notify(self, severity: str) -> bool:
        """Check if we should notify for this severity level."""
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(self.config.min_severity, 3)

    def send_alert(self, alert: dict) -> dict:
        """Send notification for an alert across all enabled channels."""
        severity = alert.get("ml_severity", "low")

        if not self.should_notify(severity):
            return {"sent": False, "reason": "severity below threshold"}

        results = {"desktop": False, "email": False, "telegram": False}

        # Desktop notification only if explicitly enabled
        if self.config.desktop_enabled:
            results["desktop"] = self._send_desktop(alert)

        if self.config.email_enabled:
            results["email"] = self._send_email(alert)

        if self.config.telegram_enabled:
            results["telegram"] = self._send_telegram(alert)

        return {"sent": any(results.values()), "channels": results}

    def _send_desktop(self, alert: dict) -> bool:
        """Send desktop notification (Linux notify-send)."""
        try:
            severity = alert.get("ml_severity", "unknown").upper()
            ref = alert.get("alert_ref", "Unknown")
            desc = alert.get("description", "No description")[:80]
            agent = alert.get("agent_name", "Unknown")
            mitre = alert.get("mitre_technique_id", "N/A")

            title = f"🚨 [{severity}] SOC Alert: {ref}"
            message = f"{desc}\nAgent: {agent} | MITRE: {mitre}"

            # Use notify-send for Linux desktop notifications
            subprocess.run(
                ["notify-send", "-u", "critical", "-t", "10000", title, message],
                capture_output=True,
                timeout=5,
            )
            logger.info("Desktop notification sent for %s", ref)
            return True

        except FileNotFoundError:
            # notify-send not installed, try zenity
            try:
                subprocess.run(
                    ["zenity", "--notification", "--text", f"{title}\n{message}"],
                    capture_output=True,
                    timeout=5,
                )
                return True
            except Exception:
                logger.warning("Desktop notification failed - no notification tool available")
                return False
        except Exception as e:
            logger.error("Desktop notification failed: %s", e)
            return False

    def _send_email(self, alert: dict) -> bool:
        """Send email notification."""
        if not self.config.email_username or not self.config.email_recipients:
            return False

        try:
            severity = alert.get("ml_severity", "unknown").upper()
            ref = alert.get("alert_ref", "Unknown")
            desc = alert.get("description", "No description")
            agent = alert.get("agent_name", "Unknown")
            mitre = alert.get("mitre_technique_id", "N/A")

            subject = f"🚨 [{severity}] SOC Alert: {ref} - {desc[:50]}"

            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #d0021b;">🚨 Security Alert: {severity}</h2>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Alert ID</b></td><td style="padding: 8px; border: 1px solid #ddd;">{ref}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Severity</b></td><td style="padding: 8px; border: 1px solid #ddd; color: {'red' if severity == 'CRITICAL' else 'orange'};">{severity}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Agent</b></td><td style="padding: 8px; border: 1px solid #ddd;">{agent}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Description</b></td><td style="padding: 8px; border: 1px solid #ddd;">{desc}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>MITRE</b></td><td style="padding: 8px; border: 1px solid #ddd;">{mitre}</td></tr>
                </table>
                <p style="margin-top: 20px;">
                    <a href="http://localhost:8501" style="background: #003366; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View in Dashboard</a>
                </p>
            </body>
            </html>
            """

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.config.email_username
            msg["To"] = ", ".join(self.config.email_recipients)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.config.email_smtp_host, self.config.email_smtp_port) as server:
                server.starttls()
                server.login(self.config.email_username, self.config.email_password)
                server.sendmail(
                    self.config.email_username,
                    self.config.email_recipients,
                    msg.as_string()
                )

            logger.info("Email notification sent for %s", ref)
            return True

        except Exception as e:
            logger.error("Email notification failed: %s", e)
            return False

    def _send_telegram(self, alert: dict) -> bool:
        """Send Telegram notification."""
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False

        try:
            severity = alert.get("ml_severity", "unknown").upper()
            ref = alert.get("alert_ref", "Unknown")
            desc = alert.get("description", "No description")
            agent = alert.get("agent_name", "Unknown")
            mitre = alert.get("mitre_technique_id", "N/A")
            confidence = alert.get("ml_confidence", 0)

            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"

            message = f"""
{emoji} *SOC Alert: {severity}*

*Alert:* {ref}
*Agent:* {agent}
*Description:* {desc}
*MITRE:* {mitre}
*Confidence:* {confidence:.0%}

[View Dashboard](http://localhost:8501)
            """

            r = httpx.post(
                f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage",
                json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )

            if r.status_code == 200:
                logger.info("Telegram notification sent for %s", ref)
                return True
            else:
                logger.warning("Telegram API returned %s", r.status_code)
                return False

        except Exception as e:
            logger.error("Telegram notification failed: %s", e)
            return False


_notifications: Optional[NotificationService] = None


def get_notifications() -> NotificationService:
    global _notifications
    if _notifications is None:
        _notifications = NotificationService()
    return _notifications
