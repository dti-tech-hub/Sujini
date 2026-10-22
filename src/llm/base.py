"""Provider abstraction for optional LLM enrichment."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.llm.schemas import InvestigationLLMOutput


class LLMError(RuntimeError):
    pass


class LLMProvider(ABC):
    name: str = "base"
    mode: str = "unknown"

    @abstractmethod
    def analyze(self, context: dict[str, Any]) -> InvestigationLLMOutput:
        """Return validated advisory analysis for one incident."""
