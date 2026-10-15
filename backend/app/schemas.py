"""Pydantic schemas for API request/response validation."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AlertOut(BaseModel):
    id: int
    alert_ref: str
    timestamp: datetime
    agent_name: str
    agent_ip: Optional[str] = None
    os_type: Optional[str] = None
    source: Optional[str] = None
    wazuh_rule_id: Optional[int] = None
    wazuh_level: Optional[int] = None
    sigma_rule_id: Optional[str] = None
    sigma_title: Optional[str] = None
    description: Optional[str] = None
    raw_log: Optional[str] = None
    ml_severity: str
    ml_confidence: Optional[float] = None
    ml_proba: Optional[Dict[str, float]] = None
    mitre_tactic: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    kill_chain_phase: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_technique: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_rag_sources: Optional[List[str]] = None
    ai_model: Optional[str] = None
    ai_generation_ms: Optional[int] = None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertList(BaseModel):
    total: int
    items: List[AlertOut]


class FeedbackIn(BaseModel):
    alert_id: int
    severity_correct: bool = True
    analyst_severity: Optional[str] = None
    is_false_positive: bool = False
    analyst_notes: Optional[str] = None
    analyst_name: Optional[str] = None


class FeedbackOut(BaseModel):
    id: int
    alert_id: int
    severity_correct: bool
    analyst_severity: Optional[str] = None
    is_false_positive: bool
    analyst_notes: Optional[str] = None
    analyst_name: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ChatRequest(BaseModel):
    message: str
    alert_id: Optional[int] = None  # optional context


class ChatResponse(BaseModel):
    answer: str
    context_alert_id: Optional[int] = None
    mode: str  # ollama | offline


class StatsOut(BaseModel):
    total_alerts: int
    severity_counts: Dict[str, int]
    status_counts: Dict[str, int]
    alerts_24h: int
    top_agents: List[Dict[str, Any]]
    top_mitre: List[Dict[str, Any]]
    avg_confidence: float
    pipeline_mode: Dict[str, Any]


class HealthOut(BaseModel):
    status: str
    database: str
    ingestion_mode: str
    llm_mode: str
    model_loaded: bool
    alerts_in_db: int
