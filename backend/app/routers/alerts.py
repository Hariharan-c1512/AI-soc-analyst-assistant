"""Alert listing, filtering, detail, and status updates."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert
from ..schemas import AlertList, AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _to_out(a: Alert) -> AlertOut:
    data = {c.name: getattr(a, c.name) for c in a.__table__.columns}
    if data.get("ml_proba"):
        try:
            data["ml_proba"] = json.loads(data["ml_proba"])
        except Exception:
            data["ml_proba"] = None
    if data.get("ai_rag_sources"):
        try:
            data["ai_rag_sources"] = json.loads(data["ai_rag_sources"])
        except Exception:
            data["ai_rag_sources"] = []
    return AlertOut(**data)


@router.get("", response_model=AlertList)
def list_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    agent: Optional[str] = Query(None),
    mitre: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.ml_severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if agent:
        query = query.filter(Alert.agent_name.ilike(f"%{agent}%"))
    if mitre:
        query = query.filter(Alert.mitre_technique_id == mitre)
    if q:
        query = query.filter(
            Alert.description.ilike(f"%{q}%")
            | Alert.sigma_title.ilike(f"%{q}%")
            | Alert.raw_log.ilike(f"%{q}%")
            | Alert.alert_ref.ilike(f"%{q}%")
        )
    total = query.count()
    items = query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()
    return AlertList(total=total, items=[_to_out(a) for a in items])


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_out(a)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_status(alert_id: int, status: str, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    allowed = {"unacknowledged", "acknowledged", "escalated", "false_positive"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {allowed}")
    a.status = status
    db.commit()
    db.refresh(a)
    return _to_out(a)
