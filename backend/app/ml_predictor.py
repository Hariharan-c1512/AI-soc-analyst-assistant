"""ML severity predictor.

Loads a trained model (Random Forest / XGBoost) from disk. If the model is
missing it falls back to a deterministic rule-based mapping from Wazuh level
so the pipeline always works end-to-end.
"""
import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd

from .config import settings
from .features import FEATURE_COLUMNS, extract_features, severity_label

logger = logging.getLogger(__name__)

# Rule-based fallback: Wazuh level → severity code
LEVEL_TO_SEVERITY = {
    15: 3, 14: 3, 13: 3, 12: 3, 11: 2, 10: 2, 9: 2, 8: 2,
    7: 1, 6: 1, 5: 1, 4: 0, 3: 0, 2: 0, 1: 0,
}


class SeverityPredictor:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path or settings.MODEL_PATH)
        self.model = None
        self.load()

    def load(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Loaded ML model from %s", self.model_path)
            except Exception as e:  # pragma: no cover
                logger.warning("Failed to load model %s: %s", self.model_path, e)
                self.model = None
        else:
            logger.info("No ML model at %s — using rule-based fallback", self.model_path)

    @property
    def loaded(self) -> bool:
        return self.model is not None

    def _fallback(self, alert: dict) -> tuple[str, float, dict]:
        level = int(alert.get("wazuh_level", 5))
        code = LEVEL_TO_SEVERITY.get(level, 1)
        proba = {label: 0.0 for label in ["low", "medium", "high", "critical"]}
        proba[severity_label(code)] = 1.0
        return severity_label(code), 0.8, proba

    def predict(self, alert: dict) -> tuple[str, float, dict]:
        """Return (severity_label, confidence, proba_dict)."""
        feats = extract_features(alert)
        df = pd.DataFrame([feats])[FEATURE_COLUMNS]

        if self.model is None:
            return self._fallback(alert)

        try:
            proba = self.model.predict_proba(df)[0]
            code = int(self.model.predict(df)[0])
            label = severity_label(code)
            conf = float(max(proba))
            proba_map = {severity_label(i): float(p) for i, p in enumerate(proba)}
            return label, round(conf, 3), proba_map
        except Exception as e:  # pragma: no cover
            logger.warning("Prediction failed (%s) — fallback used", e)
            return self._fallback(alert)

    def proba_json(self, proba: dict) -> str:
        return json.dumps(proba)


_predictor: Optional[SeverityPredictor] = None


def get_predictor() -> SeverityPredictor:
    global _predictor
    if _predictor is None:
        _predictor = SeverityPredictor()
    return _predictor
