"""Alert ingestion — polls Wazuh (live) or generates mock alerts, then runs
the full enrichment pipeline (Sigma → ML → MITRE → RAG → LLM) and persists.
"""
import json
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .llm_client import get_llm
from .mitre_mapper import map_alert
from .ml_predictor import get_predictor
from .models import Alert, Agent
from .rag_engine import get_rag
from .sigma_engine import get_sigma_engine

logger = logging.getLogger(__name__)


def normalize_wazuh_alert(w: dict) -> dict:
    """Convert a raw Wazuh alert dict into the common schema."""
    rule = w.get("rule", {})
    agent = w.get("agent", {})
    timestamp = w.get("timestamp") or datetime.now(timezone.utc).isoformat()
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    source_id = w.get("id") or w.get("_id")
    if source_id is None:
        source_id = json.dumps(w, sort_keys=True, ensure_ascii=True, default=str)
    alert_ref = "AL-" + hashlib.sha256(str(source_id).encode("utf-8")).hexdigest()[:29]

    return {
        "alert_ref": alert_ref,
        "timestamp": ts,
        "agent_name": agent.get("name", "unknown"),
        "agent_ip": agent.get("ip", ""),
        "os_type": agent.get("os", {}).get("name", "") if isinstance(agent.get("os"), dict) else str(agent.get("os", "")),
        "source": "wazuh",
        "wazuh_rule_id": rule.get("id"),
        "wazuh_level": rule.get("level"),
        "sigma_rule_id": "",
        "sigma_title": "",
        "description": w.get("rule", {}).get("description", w.get("description", "")),
        "raw_log": json.dumps(w.get("full_log") or w.get("data", {}), ensure_ascii=False)[:2000],
    }


def process_alert(db: Session, raw: dict, pipeline_only: bool = False) -> Optional[Alert]:
    """Run the enrichment pipeline on a normalized alert and persist it."""
    if not pipeline_only:
        existing = db.query(Alert).filter(Alert.alert_ref == raw["alert_ref"]).first()
        if existing:
            return existing

    sigma = get_sigma_engine()
    matched = sigma.match(raw)
    if matched:
        raw["sigma_rule_id"] = matched.rule_id
        raw["sigma_title"] = matched.title

    predictor = get_predictor()
    severity, confidence, proba = predictor.predict(raw)
    raw["ml_severity"] = severity
    raw["ml_confidence"] = confidence

    mitre = map_alert(raw)
    raw.update(mitre)

    rag = get_rag()
    if not pipeline_only:
        rag.index_alert(raw)

    rag_context = rag.retrieve(f"{raw.get('sigma_title')} {raw.get('description')} {raw.get('raw_log')}")

    llm = get_llm()
    analysis = llm.analyze_alert(raw, rag_context)

    alert = Alert(
        alert_ref=raw["alert_ref"],
        timestamp=raw["timestamp"],
        agent_name=raw["agent_name"],
        agent_ip=raw.get("agent_ip"),
        os_type=raw.get("os_type"),
        source=raw.get("source", "mock"),
        wazuh_rule_id=raw.get("wazuh_rule_id"),
        wazuh_level=raw.get("wazuh_level"),
        sigma_rule_id=raw.get("sigma_rule_id"),
        sigma_title=raw.get("sigma_title"),
        description=raw.get("description"),
        raw_log=raw.get("raw_log"),
        ml_severity=severity,
        ml_confidence=confidence,
        ml_proba=json.dumps(proba),
        mitre_tactic=raw.get("tactic"),
        mitre_tactic_id=raw.get("tactic_id"),
        mitre_technique=raw.get("technique"),
        mitre_technique_id=raw.get("technique_id"),
        kill_chain_phase=raw.get("kill_chain"),
        ai_summary=analysis["summary"],
        ai_technique=analysis["technique"],
        ai_remediation=analysis["remediation"],
        ai_rag_sources=json.dumps(analysis["rag_sources"]),
        ai_model=analysis["model"],
        ai_generation_ms=analysis["generation_ms"],
        status="unacknowledged",
    )
    db.add(alert)

    # Ensure agent record exists
    agent = db.query(Agent).filter(Agent.name == raw["agent_name"]).first()
    if not agent:
        db.add(Agent(name=raw["agent_name"], ip=raw.get("agent_ip"), os_type=raw.get("os_type"), status="active"))
    else:
        agent.last_seen = datetime.now(timezone.utc)

    db.commit()
    db.refresh(alert)

    # Send notification for critical alerts
    if severity in ("critical", "high"):
        try:
            from .notifications import get_notifications
            notif = get_notifications()
            notif.send_alert(raw)
        except Exception as e:
            logger.warning("Notification failed: %s", e)

    return alert


class WazuhIndexerClient:
    """Search alert documents from the Wazuh Indexer REST API."""

    def __init__(self):
        self.base = settings.WAZUH_INDEXER_URL.rstrip("/")
        self.user = settings.WAZUH_INDEXER_USER
        self.passwd = settings.WAZUH_INDEXER_PASSWORD

    def get_alerts(self, limit: int = 100) -> list[dict]:
        r = httpx.post(
            f"{self.base}/wazuh-alerts-*/_search",
            auth=(self.user, self.passwd),
            verify=settings.WAZUH_VERIFY_SSL,
            timeout=15,
            json={
                "size": limit,
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}],
            },
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [
            {**hit["_source"], "_id": hit.get("_id")}
            for hit in hits
            if isinstance(hit.get("_source"), dict)
        ]


class IngestionLoop:
    """Background thread that continuously ingests alerts."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ref_index = 19000

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Ingestion loop started (mode=%s)", settings.INGESTION_MODE)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        from .mock_data import build_mock_alert
        from .system_logs import SystemLogTailer

        wazuh = WazuhIndexerClient() if settings.INGESTION_MODE == "wazuh" else None
        tailer = SystemLogTailer() if settings.INGESTION_MODE == "system" else None
        while not self._stop.is_set():
            try:
                db = SessionLocal()
                try:
                    if settings.INGESTION_MODE == "wazuh" and wazuh:
                        try:
                            items = wazuh.get_alerts(limit=20)
                        except Exception as e:
                            logger.warning("Wazuh API error: %s", e)
                            items = []
                        if not items:
                            time.sleep(settings.WAZUH_POLL_INTERVAL_SECONDS)
                            continue
                        for w in items:
                            raw = normalize_wazuh_alert(w)
                            process_alert(db, raw)
                    elif settings.INGESTION_MODE == "system" and tailer:
                        events = tailer.poll()
                        if not events:
                            time.sleep(settings.SYSTEM_LOG_INTERVAL_SECONDS)
                            continue
                        from .system_logs import detect_events

                        for ev in detect_events(events):
                            self._ref_index += 1
                            ev["alert_ref"] = f"AL-{int(time.time() * 1000)}"
                            ev["timestamp"] = datetime.now(timezone.utc)
                            ev["agent_name"] = ev.get("host", "kali")
                            ev["agent_ip"] = "127.0.0.1"
                            process_alert(db, ev)
                        time.sleep(settings.SYSTEM_LOG_INTERVAL_SECONDS)
                        continue
                    else:
                        self._ref_index += 1
                        raw = build_mock_alert(self._ref_index)
                        process_alert(db, raw)
                finally:
                    db.close()
            except Exception as e:  # pragma: no cover
                logger.exception("Ingestion error: %s", e)
            interval = (
                settings.WAZUH_POLL_INTERVAL_SECONDS
                if settings.INGESTION_MODE == "wazuh"
                else settings.MOCK_ALERT_INTERVAL_SECONDS
            )
            time.sleep(interval)


_loop: Optional[IngestionLoop] = None


def get_ingestion_loop() -> IngestionLoop:
    global _loop
    if _loop is None:
        _loop = IngestionLoop()
    return _loop
