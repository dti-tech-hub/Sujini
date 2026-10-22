"""AbuseIPDB reputation provider (live, optional)."""
from __future__ import annotations

import httpx

from src.threat_intel.base import ThreatIntelError, ThreatIntelProvider, ThreatIntelResult
from src.utils.config import threat_intel_settings


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    mode = "LIVE"
    is_mock = False
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None, timeout: float | None = None) -> None:
        cfg = threat_intel_settings()
        self.api_key = (api_key if api_key is not None else cfg.get("abuseipdb_api_key", "")).strip()
        self.timeout = timeout or float(cfg.get("timeout_seconds", 8))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup_ip(self, indicator: str) -> ThreatIntelResult:
        if not self.configured:
            raise ThreatIntelError("ABUSEIPDB_API_KEY is not configured")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.endpoint,
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    params={"ipAddress": indicator, "maxAgeInDays": 90},
                )
            if response.status_code in {401, 403}:
                raise ThreatIntelError(f"AbuseIPDB rejected the API key ({response.status_code})")
            if response.status_code == 429:
                raise ThreatIntelError("AbuseIPDB rate limit exceeded (429)")
            response.raise_for_status()
            data = response.json().get("data", {}) or {}
        except httpx.HTTPError as exc:
            raise ThreatIntelError(f"AbuseIPDB request failed: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise ThreatIntelError("AbuseIPDB returned non-JSON content") from exc

        abuse_score = float(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)
        if data.get("isWhitelisted"):
            verdict, score, malicious = "clean", 0.0, False
        elif abuse_score >= 75:
            verdict, score, malicious = "malicious", abuse_score, True
        elif abuse_score >= 25:
            verdict, score, malicious = "suspicious", abuse_score, False
        else:
            verdict, score, malicious = "clean", abuse_score, False

        return ThreatIntelResult(
            provider=self.name,
            indicator=indicator,
            verdict=verdict,
            score=score,
            malicious=malicious,
            is_mock=False,
            mode="LIVE",
            details={
                "abuse_confidence_score": abuse_score,
                "total_reports": reports,
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_whitelisted": bool(data.get("isWhitelisted")),
                "last_reported_at": data.get("lastReportedAt"),
            },
        )
