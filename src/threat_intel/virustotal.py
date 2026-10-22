"""VirusTotal IP reputation provider (live, optional)."""
from __future__ import annotations

import httpx

from src.threat_intel.base import ThreatIntelError, ThreatIntelProvider, ThreatIntelResult
from src.utils.config import threat_intel_settings


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    mode = "LIVE"
    is_mock = False
    endpoint = "https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

    def __init__(self, api_key: str | None = None, timeout: float | None = None) -> None:
        cfg = threat_intel_settings()
        self.api_key = (api_key if api_key is not None else cfg.get("virustotal_api_key", "")).strip()
        self.timeout = timeout or float(cfg.get("timeout_seconds", 8))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup_ip(self, indicator: str) -> ThreatIntelResult:
        if not self.configured:
            raise ThreatIntelError("VIRUSTOTAL_API_KEY is not configured")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.endpoint.format(indicator=indicator),
                    headers={"x-apikey": self.api_key, "accept": "application/json"},
                )
            if response.status_code == 401:
                raise ThreatIntelError("VirusTotal rejected the API key (401)")
            if response.status_code == 429:
                raise ThreatIntelError("VirusTotal rate limit exceeded (429)")
            response.raise_for_status()
            data = response.json().get("data", {})
        except httpx.HTTPError as exc:
            raise ThreatIntelError(f"VirusTotal request failed: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise ThreatIntelError("VirusTotal returned non-JSON content") from exc

        attributes = data.get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        reputation = int(attributes.get("reputation", 0) or 0)

        if malicious_count >= 2 or reputation <= -10:
            verdict, score, malicious = "malicious", min(100.0, 50 + malicious_count * 5), True
        elif suspicious_count >= 2 or malicious_count == 1:
            verdict, score, malicious = "suspicious", 40.0, False
        elif harmless + undetected > 0 and malicious_count == 0:
            verdict, score, malicious = "clean", 5.0, False
        else:
            verdict, score, malicious = "unknown", 30.0, False

        return ThreatIntelResult(
            provider=self.name,
            indicator=indicator,
            verdict=verdict,
            score=float(score),
            malicious=malicious,
            is_mock=False,
            mode="LIVE",
            details={
                "last_analysis_stats": stats,
                "reputation": reputation,
                "country": attributes.get("country"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
            },
        )
