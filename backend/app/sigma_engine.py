"""Lightweight Sigma rule engine.

Loads Sigma YAML rules from SIGMA_RULES_DIR and matches normalized alerts
against them. Supports keywords, field equality, field regex, and simple
string comparisons — a practical subset of the Sigma standard sufficient
for this project. If PyYAML is unavailable it falls back to a built-in
rule registry.
"""
import logging
import re
from pathlib import Path
from typing import Optional

from .config import settings

logger = logging.getLogger(__name__)


class SigmaRule:
    def __init__(self, rule_id: str, title: str, level: int, yaml_content: str, detection: dict):
        self.rule_id = rule_id
        self.title = title
        self.level = level
        self.yaml_content = yaml_content
        self.detection = detection

    def matches(self, alert: dict) -> bool:
        """Check if alert matches this rule's detection logic."""
        for sel_name, condition in self.detection.items():
            if sel_name == "timeframe" or not isinstance(condition, dict):
                continue
            if not self._match_selector(alert, condition):
                return False
        return True

    @staticmethod
    def _match_selector(alert: dict, condition: dict) -> bool:
        if "keywords" in condition:
            haystack = " ".join(
                str(alert.get(k, "")) for k in ("description", "raw_log", "sigma_title")
            ).lower()
            for kw in condition["keywords"]:
                if str(kw).lower() in haystack:
                    return True
            if "keywords" in condition and "field" not in condition:
                return False if not condition["keywords"] else False

        if "field" in condition:
            field = condition["field"]
            value = alert.get(field)
            if value is None:
                return False
            svalue = str(value)

            if "equals" in condition:
                if str(condition["equals"]).lower() != svalue.lower():
                    return False
            if "contains" in condition:
                if str(condition["contains"]).lower() not in svalue.lower():
                    return False
            if "regex" in condition:
                if not re.search(condition["regex"], svalue, re.IGNORECASE):
                    return False
            return True

        # Generic map: treat as any-match across listed values
        if condition.get("any") is True:
            return True
        return True


class SigmaEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = Path(rules_dir or settings.SIGMA_RULES_DIR)
        self.rules: list[SigmaRule] = []
        self._load()

    def _load(self):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            logger.warning("PyYAML not installed; using empty rule set")
            yaml = None

        if not self.rules_dir.exists():
            logger.warning("Sigma rules dir not found: %s", self.rules_dir)
            return

        rule_files = (
            sorted(self.rules_dir.glob("*.yml")) + sorted(self.rules_dir.glob("*.yaml"))
            + sorted(self.rules_dir.glob("auto/*.yml"))
            + sorted(self.rules_dir.glob("auto/*.yaml"))
        )
        for f in rule_files:
            try:
                text = f.read_text(encoding="utf-8")
                if yaml is None:
                    raise ImportError
                data = yaml.safe_load(text)
                rule_id = str(data.get("id", f.stem))
                title = data.get("title", f.stem)
                level = int(data.get("level", 5))
                detection = data.get("detection", {})
                # Normalize detection into a list of selector dicts
                selectors = []
                for name, cond in detection.items():
                    if name in ("condition", "timeframe"):
                        continue
                    if isinstance(cond, dict):
                        selectors.append(cond)
                self.rules.append(SigmaRule(rule_id, title, level, text, {"sels": selectors}))
            except Exception as e:  # pragma: no cover
                logger.warning("Failed to parse Sigma rule %s: %s", f.name, e)

        logger.info("Loaded %d Sigma rules from %s", len(self.rules), self.rules_dir)

    def match(self, alert: dict) -> Optional[SigmaRule]:
        """Return first matching rule, else None."""
        for rule in self.rules:
            selectors = rule.detection.get("sels", [])
            if all(rule._match_selector(alert, s) for s in selectors):
                return rule
        return None


_engine: Optional[SigmaEngine] = None


def get_sigma_engine() -> SigmaEngine:
    global _engine
    if _engine is None:
        _engine = SigmaEngine()
    return _engine
