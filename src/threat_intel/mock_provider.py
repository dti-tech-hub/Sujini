"""Deterministic mock threat intelligence for offline demos.

Every result produced here is explicitly labelled DEMO / MOCK. Values are
derived from a hash of the indicator so demonstrations are reproducible; they
are not observations from any real intelligence feed.
"""
from __future__ import annotations

import hashlib

from src.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from src.utils.helpers import is_documentation_ip


class MockProvider(ThreatIntelProvider):
    name = "mock"
    mode = "DEMO_MOCK"
    is_mock = True

    def __init__(self, force_suspicious: bool = False) -> None:
        self.force_suspicious = force_suspicious

    @property
    def configured(self) -> bool:
        return True

    def lookup_ip(self, indicator: str) -> ThreatIntelResult:
        digest = int(hashlib.sha256(f"demo-ti:{indicator}".encode()).hexdigest()[:8], 16)
        bucket = digest % 100

        if indicator in {"198.51.100.77", "203.0.113.66"}:
            verdict, score, malicious = "malicious", 92.0, True
        elif is_documentation_ip(indicator):
            verdict, score, malicious = ("suspicious", 55.0, False) if bucket < 60 else ("clean", 5.0, False)
        elif bucket < 20:
            verdict, score, malicious = "malicious", float(70 + bucket), True
        elif bucket < 45:
            verdict, score, malicious = "suspicious", float(30 + bucket % 30), False
        else:
            verdict, score, malicious = "clean", float(bucket % 10), False

        if self.force_suspicious and not malicious:
            verdict, score = "suspicious", 50.0

        return ThreatIntelResult(
            provider=self.name,
            indicator=indicator,
            verdict=verdict,
            score=score,
            malicious=malicious,
            is_mock=True,
            mode=self.mode,
            details={
                "data_label": "DEMO / MOCK",
                "disclaimer": "Synthetic demonstration value; not real threat intelligence.",
                "deterministic_bucket": bucket,
                "documentation_range": is_documentation_ip(indicator),
            },
        )
