"""Deterministic template provider used when no LLM is configured.

It does not claim to be an LLM. The output is assembled from the
deterministic investigation agent's own evidence-linked reasoning, and the
mode is reported as DEMO TEMPLATE throughout the system.
"""
from __future__ import annotations

from typing import Any

from src.llm.base import LLMProvider
from src.llm.schemas import InvestigationLLMOutput


class DeterministicProvider(LLMProvider):
    name = "deterministic_template"
    mode = "DEMO_TEMPLATE"

    def analyze(self, context: dict[str, Any]) -> InvestigationLLMOutput:
        return InvestigationLLMOutput(
            classification=context.get("baseline_classification", "suspicious_activity"),
            confidence=float(context.get("baseline_confidence", 0.5)),
            summary=context.get("baseline_summary", "Deterministic investigation summary."),
            reasoning=list(context.get("baseline_reasoning", [])),
            recommended_next_steps=list(context.get("baseline_next_steps", [])),
            mitre_hypotheses=[],
        )
