"""LLM provider selection."""
from __future__ import annotations

from src.llm.base import LLMProvider
from src.llm.deterministic import DeterministicProvider
from src.llm.openai_compatible import OpenAICompatibleProvider
from src.utils.config import llm_settings


def build_llm_provider() -> tuple[LLMProvider, str]:
    """Return (provider, mode_label).

    mode_label is one of: LIVE_LLM, DEMO_TEMPLATE, FALLBACK_TEMPLATE.
    """
    settings = llm_settings()
    if settings.get("configured"):
        try:
            return OpenAICompatibleProvider(settings), "LIVE_LLM"
        except Exception:
            return DeterministicProvider(), "FALLBACK_TEMPLATE"
    return DeterministicProvider(), "DEMO_TEMPLATE"


def llm_status() -> dict[str, object]:
    settings = llm_settings()
    return {
        "enabled": bool(settings.get("enabled")),
        "configured": bool(settings.get("configured")),
        "mode": "LIVE_LLM" if settings.get("configured") else "DEMO_TEMPLATE",
        "provider": "openai_compatible" if settings.get("configured") else "deterministic_template",
        "model": settings.get("model") if settings.get("configured") else None,
        "note": None if settings.get("configured") else "LLM NOT CONFIGURED - deterministic evidence templates are used.",
    }
