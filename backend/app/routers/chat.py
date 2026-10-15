"""AI chat endpoint with optional alert context."""
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..llm_client import get_llm
from ..models import Alert
from ..rag_engine import get_rag
from ..schemas import ChatRequest, ChatResponse

router = APIRouter(prefix="/chat", tags=["chat"])


def _build_chat_prompt(message: str, alert: Optional[Alert], context: list) -> str:
    parts = ["task: soc_chat"]
    if alert:
        parts.append(
            json.dumps({
                "alert": {
                    "alert_ref": alert.alert_ref,
                    "description": alert.description,
                    "agent_name": alert.agent_name,
                    "ml_severity": alert.ml_severity,
                    "mitre_technique": alert.mitre_technique,
                    "mitre_technique_id": alert.mitre_technique_id,
                }
            }, ensure_ascii=False)
        )
    if context:
        ctx = "\n".join(f"- {c.get('alert_ref')} ({c.get('similarity', 0):.2f}): {c.get('description')}" for c in context)
        parts.append(f"similar_incidents:\n{ctx}")
    parts.append(f"question: {message}")
    return "\n".join(parts)


@router.post("", response_model=ChatResponse)
def chat(req: ChatRequest, db: Session = Depends(get_db)):
    llm = get_llm()
    rag = get_rag()

    alert = None
    if req.alert_id:
        alert = db.get(Alert, req.alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

    context = rag.retrieve(req.message)
    prompt = _build_chat_prompt(req.message, alert, context)
    t0 = time.monotonic()

    answer = None
    if not llm.is_ollama:
        # Offline mode: answer common operational questions with live DB stats.
        answer = _offline_answer(db, req.message, alert)
    if answer is None:
        answer = llm.generate(prompt, system="You are a SOC analyst assistant helping analyze security alerts.")

    mode = "ollama" if llm.is_ollama else "offline"
    return ChatResponse(answer=answer, context_alert_id=req.alert_id, mode=mode)


def _offline_answer(db: Session, message: str, alert: Optional[Alert]) -> str | None:
    """Rule-based answers for common questions when no LLM is available."""
    m = message.lower()

    def counts() -> str:
        from sqlalchemy import func

        total = db.query(func.count(Alert.id)).scalar() or 0
        sev = dict(db.query(Alert.ml_severity, func.count(Alert.id)).group_by(Alert.ml_severity).all())
        out = f"[Offline analysis] There are {total} alerts in the database:\n"
        for s in ["low", "medium", "high", "critical"]:
            out += f"- {s}: {sev.get(s, 0)}\n"
        return out

    if any(k in m for k in ["total", "how many", "count", "stats", "summary of alerts"]):
        return counts()
    if "most common" in m and ("technique" in m or "mitre" in m):
        from sqlalchemy import desc, func

        top = (
            db.query(Alert.mitre_technique_id, func.count(Alert.id))
            .group_by(Alert.mitre_technique_id)
            .order_by(desc(func.count(Alert.id))).limit(5).all()
        )
        if not top:
            return "No MITRE-mapped alerts yet."
        out = "[Offline analysis] Most common MITRE techniques:\n"
        for tid, c in top:
            out += f"- {tid}: {c} alerts\n"
        return out + "Focus your triage on the top technique first."
    if "critical" in m and ("count" in m or "how many" in m or "alerts" in m):
        from sqlalchemy import func

        c = db.query(func.count(Alert.id)).filter(Alert.ml_severity == "critical").scalar() or 0
        return f"[Offline analysis] There are {c} critical alerts right now."
    if "top agent" in m or "which host" in m or "most alerts" in m:
        from sqlalchemy import desc, func

        top = db.query(Alert.agent_name, func.count(Alert.id)).group_by(Alert.agent_name).order_by(desc(func.count(Alert.id))).limit(3).all()
        if not top:
            return "No alert data yet."
        return "[Offline analysis] Top alert sources: " + ", ".join(f"{a} ({c})" for a, c in top) + "."
    if alert:
        return (
            f"[Offline analysis]\n\nIncident Summary:\n{alert.description} on {alert.agent_name} "
            f"(severity {alert.ml_severity}).\n\nMITRE: {alert.mitre_technique} ({alert.mitre_technique_id})\n\n"
            f"Remediation:\n{alert.ai_remediation or 'See alert detail for remediation steps.'}"
        )
    return None
