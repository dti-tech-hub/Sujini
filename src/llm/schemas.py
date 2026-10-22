"""Validated schemas for AI-generated investigation output."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ALLOWED_CLASSIFICATIONS = {
    "brute_force",
    "account_compromise",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "malicious_ip",
    "abnormal_traffic",
    "recon_scanning",
    "suspicious_user_agent",
    "prompt_injection_attempt",
    "suspicious_activity",
    "benign_or_unknown",
}

_DANGEROUS = re.compile(
    r"(?i)(rm\s+-rf|format\s+[a-z]:|shutdown|del\s+/[sf]|powershell\s+-enc|curl\s+http|wget\s+http|nc\s+-e|bash\s+-i)"
)


class InvestigationLLMOutput(BaseModel):
    """Strict schema for an optional LLM enrichment.

    The LLM is advisory only. Its output never selects or executes a response
    action; the policy engine and human approval remain authoritative.
    """

    model_config = ConfigDict(extra="forbid")

    classification: str = Field(max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=4000)
    reasoning: list[str] = Field(default_factory=list, max_length=12)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=10)
    mitre_hypotheses: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, value: str) -> str:
        normalized = value.strip().lower().replace(" ", "_").replace("-", "_")
        if normalized not in ALLOWED_CLASSIFICATIONS:
            raise ValueError(f"Classification not in allowlist: {normalized}")
        return normalized

    @field_validator("reasoning", "recommended_next_steps", "mitre_hypotheses")
    @classmethod
    def validate_text_list(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            text = " ".join(str(value).split())[:500]
            if not text:
                continue
            if _DANGEROUS.search(text):
                raise ValueError("Generated text contains a prohibited destructive command pattern")
            cleaned.append(text)
        return cleaned

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        text = " ".join(value.split())[:4000]
        if not text:
            raise ValueError("Summary must not be empty")
        return text
