"""Enhanced API endpoints for Threat Intel, IR, Training, and Compliance."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


# ============================================================
# THREAT INTEL ENDPOINTS
# ============================================================
class TIRequest(BaseModel):
    ip: str


@router.post("/threat-intel/lookup")
def lookup_ip(request: TIRequest):
    """Look up an IP address in threat intelligence databases."""
    from ..threat_intel import get_threat_intel
    ti = get_threat_intel()
    result = ti.lookup_ip(request.ip)
    return {
        "ip": result.ip,
        "is_malicious": result.is_malicious,
        "threat_score": result.threat_score,
        "country": result.country,
        "isp": result.ISP,
        "reports": result.reports,
        "source": result.source,
        "details": result.details,
    }


# ============================================================
# INCIDENT RESPONSE ENDPOINTS
# ============================================================
class IRRequest(BaseModel):
    action: str
    target: str
    params: dict = {}


@router.post("/ir/action")
def execute_ir_action(request: IRRequest):
    """Execute an incident response action."""
    from ..incident_response import get_incident_response
    ir = get_incident_response(dry_run=True)
    result = ir.execute_action(request.action, request.target, request.params)
    return {
        "action": result.action,
        "target": result.target,
        "status": result.status,
        "message": result.message,
        "timestamp": result.timestamp,
        "requires_approval": result.requires_approval,
    }


@router.get("/ir/log")
def get_ir_log():
    """Get incident response action log."""
    from ..incident_response import get_incident_response
    ir = get_incident_response()
    return ir.get_action_log()


# ============================================================
# TRAINING ENDPOINTS
# ============================================================
@router.get("/training/scenarios")
def list_scenarios():
    """List all available attack simulation scenarios."""
    from ..attack_simulation import get_simulator
    sim = get_simulator()
    return sim.get_scenario_list()


@router.get("/training/scenario/{scenario_id}")
def get_scenario(scenario_id: str):
    """Get scenario details."""
    from ..attack_simulation import get_simulator
    sim = get_simulator()
    return sim.start_scenario(scenario_id)


@router.post("/training/advance")
def advance_scenario(request: dict):
    """Advance to next step in the scenario."""
    from ..attack_simulation import get_simulator
    sim = get_simulator()
    return sim.advance_step()


@router.get("/training/exercise/{scenario_id}")
def get_exercise(scenario_id: str):
    """Get detection exercise for a scenario."""
    from ..attack_simulation import get_simulator
    sim = get_simulator()
    return sim.get_detection_exercise(scenario_id)


# ============================================================
# COMPLIANCE ENDPOINTS
# ============================================================
class ComplianceRequest(BaseModel):
    standard: str
    stats: dict = {}


@router.post("/compliance/generate")
def generate_compliance_report(request: ComplianceRequest):
    """Generate a compliance report."""
    from ..compliance import get_compliance
    from ..database import SessionLocal
    from ..models import Alert

    db = SessionLocal()
    try:
        alerts = []
        for a in db.query(Alert).limit(500).all():
            alerts.append({
                "alert_ref": a.alert_ref,
                "ml_severity": a.ml_severity,
                "description": a.description,
                "mitre_technique_id": a.mitre_technique_id,
                "agent_name": a.agent_name,
            })
    finally:
        db.close()

    compliance = get_compliance()
    report = compliance.generate_report(request.standard, alerts, request.stats)

    return {
        "standard": report.standard,
        "report_date": report.report_date,
        "summary": report.summary,
        "findings": report.findings,
        "recommendations": report.recommendations,
        "score": report.score,
        "status": report.status,
    }
