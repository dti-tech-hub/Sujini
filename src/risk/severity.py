"""Severity and risk-level helpers."""
from __future__ import annotations

from src.utils.config import get_risk_rules

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def normalize_severity(value: str | None, default: str = "MEDIUM") -> str:
    text = (value or "").strip().upper()
    return text if text in SEVERITY_ORDER else default


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def risk_level_for(score: float) -> str:
    rules = get_risk_rules().get("thresholds", {})
    if score <= float(rules.get("low_max", 24)):
        return "LOW"
    if score <= float(rules.get("medium_max", 49)):
        return "MEDIUM"
    if score <= float(rules.get("high_max", 74)):
        return "HIGH"
    return "CRITICAL"


def level_index(level: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get((level or "").upper(), 0)
