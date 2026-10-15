"""Capture complete pipeline output for 3 real examples.

Shows the full flow: alert → Sigma match → ML prediction → MITRE mapping → RAG → LLM analysis.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.database import SessionLocal, init_db
from backend.app.models import Alert


def capture_examples():
    init_db()
    db = SessionLocal()
    try:
        # Get the 3 most recent alerts
        alerts = db.query(Alert).order_by(Alert.id.desc()).limit(3).all()

        output = []
        for i, alert in enumerate(alerts, 1):
            example = {
                "example": i,
                "alert_ref": alert.alert_ref,
                "timestamp": str(alert.timestamp),
                "agent": alert.agent_name,
                "agent_ip": alert.agent_ip,
                "os": alert.os_type,
                "source": alert.source,
                "description": alert.description,
                "raw_log": alert.raw_log[:500] if alert.raw_log else "",
                "sigma_rule_id": alert.sigma_rule_id,
                "sigma_title": alert.sigma_title,
                "ml_severity": alert.ml_severity,
                "ml_confidence": alert.ml_confidence,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_tactic_id": alert.mitre_tactic_id,
                "mitre_technique": alert.mitre_technique,
                "mitre_technique_id": alert.mitre_technique_id,
                "kill_chain_phase": alert.kill_chain_phase,
                "ai_summary": alert.ai_summary,
                "ai_technique": alert.ai_technique,
                "ai_remediation": alert.ai_remediation,
                "ai_model": alert.ai_model,
                "ai_generation_ms": alert.ai_generation_ms,
                "status": alert.status,
            }
            output.append(example)

            print(f"\n{'='*70}")
            print(f"EXAMPLE {i}: {alert.alert_ref}")
            print(f"{'='*70}")
            print(f"Attack:       {alert.description}")
            print(f"Agent:        {alert.agent_name} ({alert.agent_ip}) [{alert.os_type}]")
            print(f"Sigma Match:  {alert.sigma_rule_id} - {alert.sigma_title}")
            print(f"ML Severity:  {alert.ml_severity.upper()} (confidence: {alert.ml_confidence:.3f})")
            print(f"MITRE:        {alert.mitre_technique_id} - {alert.mitre_technique}")
            print(f"Tactic:       {alert.mitre_tactic_id} - {alert.mitre_tactic}")
            print(f"Kill Chain:   {alert.kill_chain_phase}")
            print(f"\nAI Analysis ({alert.ai_model}, {alert.ai_generation_ms}ms):")
            print(f"  Summary:     {alert.ai_summary[:200]}...")
            print(f"  Remediation: {alert.ai_remediation[:200]}...")

        # Save to file
        result_dir = Path("data/results")
        result_dir.mkdir(parents=True, exist_ok=True)
        result_path = result_dir / "real_examples.json"
        result_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        print(f"\n{'='*70}")
        print(f"Examples saved -> {result_path}")

    finally:
        db.close()


if __name__ == "__main__":
    capture_examples()
