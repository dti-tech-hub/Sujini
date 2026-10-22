"""Compiled rule-based detection signatures."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import unquote_plus

from src.security.sanitization import sanitize_text
from src.utils.config import get_detection_rules


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    category: str
    severity: str
    description: str
    matched_fields: list[str] = field(default_factory=list)
    evidence: str = ""
    mitre: list[str] = field(default_factory=list)


@dataclass
class CompiledRule:
    id: str
    name: str
    category: str
    severity: str
    fields: list[str]
    patterns: list[re.Pattern[str]]
    description: str
    mitre: list[str]


@lru_cache(maxsize=1)
def compiled_rules() -> list[CompiledRule]:
    rules = []
    for item in get_detection_rules().get("rules", []):
        try:
            patterns = [re.compile(pattern) for pattern in item.get("patterns", [])]
        except re.error as exc:  # configuration error should fail loudly at startup
            raise ValueError(f"Invalid regex in detection rule {item.get('id')}: {exc}") from exc
        rules.append(
            CompiledRule(
                id=str(item["id"]),
                name=str(item["name"]),
                category=str(item["category"]),
                severity=str(item["severity"]).upper(),
                fields=list(item.get("fields", [])),
                patterns=patterns,
                description=str(item.get("description", "")),
                mitre=list(item.get("mitre", [])),
            )
        )
    return rules


def _field_text(event: dict[str, Any], field: str) -> str:
    if field == "request_body":
        raw = event.get("raw_event") or {}
        value = str(raw.get("_sanitized_request_body") or raw.get("request_body") or raw.get("body") or "")
    else:
        value = event.get(field)
        if value is None and field in {"message", "user_agent"}:
            raw = event.get("raw_event") or {}
            value = raw.get(field)
        value = str(value or "")
    if field in {"endpoint", "request_body", "message"} and "%" in value:
        # Inspect both encoded and decoded forms; still purely passive.
        value = value + " " + unquote_plus(value)
    return value


def evaluate_rules(event: dict[str, Any]) -> list[RuleHit]:
    """Evaluate passive signatures against a normalized event mapping."""
    hits: list[RuleHit] = []
    for rule in compiled_rules():
        matched_fields: list[str] = []
        evidence = ""
        haystack = " ".join(_field_text(event, f) for f in rule.fields)
        if not haystack.strip():
            continue
        for pattern in rule.patterns:
            match = pattern.search(haystack)
            if match:
                for field in rule.fields:
                    text = _field_text(event, field)
                    if text and pattern.search(text):
                        matched_fields.append(field)
                if not matched_fields:
                    matched_fields = list(rule.fields)
                evidence = sanitize_text(match.group(0), 200)
                break
        if matched_fields:
            hits.append(
                RuleHit(
                    rule_id=rule.id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_fields=sorted(set(matched_fields)),
                    evidence=evidence,
                    mitre=rule.mitre,
                )
            )
    return hits
