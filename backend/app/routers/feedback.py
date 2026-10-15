"""Analyst feedback endpoints — stored for retraining."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Feedback
from ..schemas import FeedbackIn, FeedbackOut

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post("", response_model=FeedbackOut)
def submit_feedback(req: FeedbackIn, db: Session = Depends(get_db)):
    alert = db.get(Alert, req.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    fb = Feedback(
        alert_id=req.alert_id,
        severity_correct=req.severity_correct,
        analyst_severity=req.analyst_severity,
        is_false_positive=req.is_false_positive,
        analyst_notes=req.analyst_notes,
        analyst_name=req.analyst_name,
    )
    if req.is_false_positive:
        alert.status = "false_positive"
    db.add(fb)
    db.commit()
    db.refresh(fb)
    return FeedbackOut.model_validate(fb)


@router.get("", response_model=list[FeedbackOut])
def list_feedback(alert_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(Feedback)
    if alert_id is not None:
        q = q.filter(Feedback.alert_id == alert_id)
    return [FeedbackOut.model_validate(f) for f in q.order_by(Feedback.created_at.desc()).all()]
