"""OpenAI-compatible chat-completions provider (optional)."""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from src.llm.base import LLMError, LLMProvider
from src.llm.prompts import build_investigation_messages
from src.llm.schemas import InvestigationLLMOutput
from src.utils.config import llm_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
_JSON_BLOCK = re.compile(r"\{[\s\S]*\}")


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"
    mode = "LIVE_LLM"

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.settings = settings or llm_settings()
        if not self.settings.get("configured"):
            raise LLMError("LLM is not configured (LLM_ENABLED + LLM_API_KEY required)")
        self.base_url = str(self.settings["base_url"]).rstrip("/")
        self.model = str(self.settings["model"])

    def _request(self, messages: list[dict[str, str]], use_json_mode: bool) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": float(self.settings.get("temperature", 0.0)),
            "max_tokens": int(self.settings.get("max_tokens", 900)),
        }
        if use_json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {
            "Authorization": f"Bearer {self.settings['api_key']}",
            "Content-Type": "application/json",
        }
        timeout = float(self.settings.get("timeout_seconds", 25))
        with httpx.Client(timeout=timeout) as client:
            response = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
        if response.status_code == 400 and use_json_mode:
            return self._request(messages, use_json_mode=False)
        if response.status_code >= 400:
            raise LLMError(f"LLM endpoint returned HTTP {response.status_code}")
        try:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise LLMError("LLM response did not match the chat-completions shape") from exc

    def analyze(self, context: dict[str, Any]) -> InvestigationLLMOutput:
        messages = build_investigation_messages(context)
        try:
            content = self._request(messages, use_json_mode=True)
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from exc
        text = (content or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        match = _JSON_BLOCK.search(text)
        if not match:
            raise LLMError("LLM response contained no JSON object")
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise LLMError("LLM returned invalid JSON") from exc
        try:
            result = InvestigationLLMOutput.model_validate(payload)
        except Exception as exc:
            raise LLMError(f"LLM JSON failed schema validation: {str(exc)[:300]}") from exc
        logger.info(
            "llm_analysis",
            extra={"provider": self.name, "model": self.model, "classification": result.classification},
        )
        return result
