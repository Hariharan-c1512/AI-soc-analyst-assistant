"""ORM models for the SOC analyst database."""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_ref = Column(String(32), unique=True, index=True)  # e.g. AL-19285

    timestamp = Column(DateTime, default=utcnow, index=True)
    agent_name = Column(String(128), index=True)
    agent_ip = Column(String(64))
    os_type = Column(String(32))

    source = Column(String(32))  # wazuh / mock
    wazuh_rule_id = Column(Integer)
    wazuh_level = Column(Integer)

    sigma_rule_id = Column(String(32))
    sigma_title = Column(String(256))

    description = Column(Text)
    raw_log = Column(Text)

    # ML severity prediction
    ml_severity = Column(String(16), index=True)  # critical|high|medium|low
    ml_confidence = Column(Float)
    ml_proba = Column(Text)  # JSON dict of class probabilities

    # MITRE ATT&CK
    mitre_tactic = Column(String(128))
    mitre_tactic_id = Column(String(16))
    mitre_technique = Column(String(128))
    mitre_technique_id = Column(String(32))
    kill_chain_phase = Column(String(64))

    # AI analysis
    ai_summary = Column(Text)
    ai_technique = Column(Text)
    ai_remediation = Column(Text)
    ai_rag_sources = Column(Text)  # JSON list of related alert refs
    ai_model = Column(String(64))
    ai_generation_ms = Column(Integer)

    status = Column(String(32), default="unacknowledged", index=True)  # unacknowledged|acknowledged|escalated|false_positive
    created_at = Column(DateTime, default=utcnow)


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), index=True)
    severity_correct = Column(Boolean, default=True)
    analyst_severity = Column(String(16))
    is_false_positive = Column(Boolean, default=False)
    analyst_notes = Column(Text)
    analyst_name = Column(String(64))
    created_at = Column(DateTime, default=utcnow)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, index=True)
    ip = Column(String(64))
    os_type = Column(String(32))
    status = Column(String(32), default="active")
    last_seen = Column(DateTime, default=utcnow)


class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    id = Column(Integer, primary_key=True)
    rule_id = Column(String(32), unique=True, index=True)
    title = Column(String(256))
    description = Column(Text)
    level = Column(Integer)
    mitre_technique_id = Column(String(32))
    yaml_content = Column(Text)


class ModelMetadata(Base):
    __tablename__ = "model_metadata"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(64))
    version = Column(String(32))
    accuracy = Column(Float)
    f1_score = Column(Float)
    training_samples = Column(Integer)
    trained_at = Column(DateTime, default=utcnow)
