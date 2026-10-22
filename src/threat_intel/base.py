"""Threat-intelligence provider interface and result types."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ThreatIntelError(RuntimeError):
    """Raised when a live provider cannot complete a lookup."""


@dataclass
class ThreatIntelResult:
    provider: str
    indicator: str
    indicator_type: str = "ip"
    verdict: str = "unknown"  # malicious | suspicious | clean | unknown | private | error
    score: float = 0.0  # 0-100 confidence/abuse score from provider
    malicious: bool = False
    is_mock: bool = True
    mode: str = "DEMO_MOCK"
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "provider": self.provider,
            "verdict": self.verdict,
            "score": float(self.score),
            "malicious": bool(self.malicious),
            "details": self.details,
            "is_mock": self.is_mock,
            "mode": self.mode,
            "error": self.error,
        }


class ThreatIntelProvider(ABC):
    name: str = "base"
    mode: str = "unknown"
    is_mock: bool = False

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Whether the provider has the credentials required to run."""

    @abstractmethod
    def lookup_ip(self, indicator: str) -> ThreatIntelResult:
        """Look up one IP address. Raises ThreatIntelError on failure."""
