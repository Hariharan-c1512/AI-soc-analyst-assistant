"""Statistics and health endpoints."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..llm_client import get_llm
from ..ml_predictor import get_predictor
from ..models import Alert, ModelMetadata
from ..schemas import HealthOut, StatsOut

router = APIRouter(tags=["system"])


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Alert.id)).scalar() or 0

    sev_counts = dict(
        db.query(Alert.ml_severity, func.count(Alert.id))
        .group_by(Alert.ml_severity).all()
    )
    sev_counts = {k: sev_counts.get(k, 0) for k in ["low", "medium", "high", "critical"]}

    status_counts = dict(
        db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    )

    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    alerts_24h = db.query(func.count(Alert.id)).filter(Alert.timestamp >= since_24h).scalar() or 0

    top_agents = [
        {"agent": a, "count": c}
        for a, c in db.query(Alert.agent_name, func.count(Alert.id))
        .group_by(Alert.agent_name).order_by(desc(func.count(Alert.id))).limit(8).all()
    ]

    top_mitre = [
        {"technique_id": t or "N/A", "count": c}
        for t, c in db.query(Alert.mitre_technique_id, func.count(Alert.id))
        .group_by(Alert.mitre_technique_id).order_by(desc(func.count(Alert.id))).limit(6).all()
    ]

    avg_conf = db.query(func.avg(Alert.ml_confidence)).scalar() or 0.0

    return StatsOut(
        total_alerts=total,
        severity_counts=sev_counts,
        status_counts=status_counts,
        alerts_24h=alerts_24h,
        top_agents=top_agents,
        top_mitre=top_mitre,
        avg_confidence=round(float(avg_conf), 3),
        pipeline_mode={
            "ingestion": settings.INGESTION_MODE,
            "llm": settings.LLM_MODE,
            "llm_model": settings.OLLAMA_MODEL,
        },
    )


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)):
    total = db.query(func.count(Alert.id)).scalar() or 0
    llm = get_llm()
    pred = get_predictor()
    return HealthOut(
        status="ok",
        database=settings.DATABASE_URL.split(":")[0],
        ingestion_mode=settings.INGESTION_MODE,
        llm_mode=settings.LLM_MODE,
        model_loaded=pred.loaded,
        alerts_in_db=total,
    )


@router.get("/model-info")
def model_info(db: Session = Depends(get_db)):
    meta = db.query(ModelMetadata).order_by(desc(ModelMetadata.trained_at)).first()
    if not meta:
        return {"model": None}
    return {
        "model_name": meta.model_name,
        "version": meta.version,
        "accuracy": meta.accuracy,
        "f1_score": meta.f1_score,
        "training_samples": meta.training_samples,
        "trained_at": meta.trained_at.isoformat(),
    }
