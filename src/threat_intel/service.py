"""Threat-intelligence enrichment orchestration with explicit fallback modes."""
from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.database import repository
from src.threat_intel.abuseipdb import AbuseIPDBProvider
from src.threat_intel.base import ThreatIntelError, ThreatIntelProvider, ThreatIntelResult
from src.threat_intel.mock_provider import MockProvider
from src.threat_intel.virustotal import VirusTotalProvider
from src.utils.config import threat_intel_settings
from src.utils.helpers import is_documentation_ip, is_public_ip, utcnow
from src.utils.logging import get_logger

logger = get_logger(__name__)


def make_providers(include_unconfigured: bool = False) -> dict[str, ThreatIntelProvider]:
    return {
        "virustotal": VirusTotalProvider(),
        "abuseipdb": AbuseIPDBProvider(),
        "mock": MockProvider(),
    }


class ThreatIntelService:
    def __init__(self, session: Session | None = None) -> None:
        self.session = session
        self.config = threat_intel_settings()
        self.providers = make_providers()

    @property
    def live_configured(self) -> bool:
        return any(self.providers[name].configured for name in ("virustotal", "abuseipdb"))

    def _cache_lookup(self, indicator: str, provider: str) -> ThreatIntelResult | None:
        if not self.session:
            return None
        ttl = int(self.config.get("cache_ttl_minutes", 60))
        cached = repository.latest_threat_intel(
            self.session, indicator, provider, utcnow() - timedelta(minutes=ttl)
        )
        if not cached or cached.mode != "LIVE":
            return None
        details = dict(cached.details or {})
        details["cached"] = True
        details["cached_from_incident"] = cached.incident_id
        return ThreatIntelResult(
            provider=cached.provider,
            indicator=cached.indicator,
            indicator_type=cached.indicator_type,
            verdict=cached.verdict,
            score=float(cached.score or 0),
            malicious=bool(cached.malicious),
            is_mock=bool(cached.is_mock),
            mode=cached.mode,
            details=details,
        )

    @staticmethod
    def _local_result(indicator: str, verdict: str, mode: str, explanation: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider="local_scope",
            indicator=indicator,
            verdict=verdict,
            score=0.0,
            malicious=False,
            is_mock=False,
            mode=mode,
            details={"explanation": explanation, "data_label": "NO_EXTERNAL_LOOKUP"},
        )

    def _query_provider(self, provider: ThreatIntelProvider, indicator: str) -> tuple[ThreatIntelResult | None, str | None]:
        cached = self._cache_lookup(indicator, provider.name)
        if cached:
            return cached, None
        try:
            return provider.lookup_ip(indicator), None
        except ThreatIntelError as exc:
            logger.warning("Threat intel provider %s failed: %s", provider.name, exc)
            return None, str(exc)
        except Exception as exc:  # defensive: a provider bug must not break investigation
            logger.exception("Unexpected threat intel provider error")
            return None, f"{type(exc).__name__}: {exc}"

    def lookup_ip(self, indicator: str, *, persist_incident_id: str | None = None) -> dict[str, Any]:
        indicator = (indicator or "").strip()
        try:
            address = ipaddress.ip_address(indicator)
        except ValueError:
            result = ThreatIntelResult(
                provider="validator", indicator=indicator, verdict="error", is_mock=False,
                mode="INVALID", error="Indicator is not a valid IP address",
            )
            return self._summarize([result], indicator)

        if not self.config.get("enabled", True):
            result = self._local_result(indicator, "unknown", "DISABLED", "Threat intelligence is disabled by configuration.")
            return self._summarize([result], indicator)

        results: list[ThreatIntelResult] = []
        errors: dict[str, str] = {}

        if address.is_private or address.is_loopback or address.is_link_local:
            if is_documentation_ip(indicator):
                results.append(MockProvider().lookup_ip(indicator))
            else:
                results.append(
                    self._local_result(
                        indicator, "private", "NO_EXTERNAL_LOOKUP",
                        "Private/loopback indicator; external providers are intentionally not queried.",
                    )
                )
        elif is_documentation_ip(indicator):
            # Documentation/test-net ranges are synthetic demo indicators. A
            # live provider would return no meaningful data, so we use the
            # clearly labelled mock provider even when keys are configured.
            results.append(MockProvider().lookup_ip(indicator))
        else:
            configured = [
                self.providers[name]
                for name in self.config.get("providers", ["virustotal", "abuseipdb"])
                if name in self.providers and self.providers[name].configured
            ]
            for provider in configured:
                result, error = self._query_provider(provider, indicator)
                if result:
                    results.append(result)
                if error:
                    errors[provider.name] = error

            if not configured and self.config.get("mock_fallback", True):
                mock = self.providers["mock"].lookup_ip(indicator)
                mock.details = {
                    **(mock.details or {}),
                    "note": "No live threat-intelligence credentials configured; DEMO / MOCK data used.",
                }
                results.append(mock)
            elif not results and self.config.get("mock_fallback", True):
                mock = self.providers["mock"].lookup_ip(indicator)
                mock.mode = "DEMO_MOCK_FALLBACK"
                mock.details = {
                    **(mock.details or {}),
                    "fallback_reason": "All configured live provider queries failed.",
                    "provider_errors": errors,
                }
                results.append(mock)

        summary = self._summarize(results, indicator)
        summary["provider_errors"] = errors

        if self.session and persist_incident_id:
            for result in results:
                repository.add_threat_intelligence(
                    self.session, persist_incident_id, **result.to_record()
                )
        return summary

    @staticmethod
    def _summarize(results: list[ThreatIntelResult], indicator: str) -> dict[str, Any]:
        usable = [item for item in results if item.verdict not in {"error"}]
        if not usable and results:
            # Preserve the explicit failure mode (for example INVALID) rather
            # than collapsing an unqueried indicator into "UNAVAILABLE".
            modes = {item.mode for item in results}
            return {
                "indicator": indicator,
                "verdict": "error",
                "score": 0.0,
                "malicious": False,
                "suspicious": False,
                "mode": next(iter(modes)) if len(modes) == 1 else "UNAVAILABLE",
                "is_mock": any(item.is_mock for item in results),
                "conflict": False,
                "results": [item.__dict__ for item in results],
                "details": {
                    "indicators": [indicator],
                    "provider_count": 0,
                    "providers": [item.provider for item in results],
                    "provider_verdicts": {item.provider: item.verdict for item in results},
                    "errors": {item.provider: item.error for item in results if item.error},
                    "conflict": False,
                    "mock_disclaimer": None,
                },
            }
        malicious = [item for item in usable if item.verdict == "malicious" or item.malicious]
        suspicious = [item for item in usable if item.verdict == "suspicious"]
        clean = [item for item in usable if item.verdict == "clean"]
        private = [item for item in usable if item.verdict == "private"]

        if malicious:
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        elif private:
            verdict = "private"
        elif clean:
            verdict = "clean"
        else:
            verdict = "unknown"

        score = max((float(item.score or 0) for item in usable), default=0.0)
        modes = {item.mode for item in usable}
        is_mock = any(item.is_mock for item in usable) if usable else False
        if modes == {"LIVE"}:
            mode = "LIVE"
        elif modes == {"DEMO_MOCK"}:
            mode = "DEMO_MOCK"
        elif modes == {"DEMO_MOCK_FALLBACK"}:
            mode = "DEMO_MOCK_FALLBACK"
        elif modes == {"NO_EXTERNAL_LOOKUP"}:
            mode = "NO_EXTERNAL_LOOKUP"
        elif len(modes) > 1:
            mode = "MIXED"
        elif modes:
            mode = next(iter(modes))
        else:
            mode = "UNAVAILABLE"

        verdicts = {item.verdict for item in usable}
        conflict = "malicious" in verdicts and "clean" in verdicts
        details = {
            "indicators": [indicator],
            "provider_count": len(usable),
            "providers": [item.provider for item in usable],
            "provider_verdicts": {item.provider: item.verdict for item in usable},
            "conflict": conflict,
            "mock_disclaimer": "DEMO / MOCK - synthetic values, not real threat intelligence." if is_mock else None,
        }
        return {
            "indicator": indicator,
            "verdict": verdict,
            "score": round(float(score), 2),
            "malicious": bool(malicious),
            "suspicious": bool(suspicious),
            "mode": mode,
            "is_mock": is_mock,
            "conflict": conflict,
            "results": [item.__dict__ for item in results],
            "details": details,
        }

    def enrich_ips(self, indicators: list[str], incident_id: str | None = None) -> dict[str, Any]:
        unique = []
        for value in indicators:
            if value and value not in unique:
                unique.append(value)
        summaries = [self.lookup_ip(value, persist_incident_id=incident_id) for value in unique[:10]]
        malicious = [item for item in summaries if item["malicious"]]
        suspicious = [item for item in summaries if item["suspicious"]]
        if malicious:
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        elif summaries and all(item["verdict"] == "private" for item in summaries):
            verdict = "private"
        elif any(item["verdict"] == "clean" for item in summaries):
            verdict = "clean"
        else:
            verdict = "unknown"
        modes = {item["mode"] for item in summaries}
        return {
            "indicators": summaries,
            "verdict": verdict,
            "max_score": max((item["score"] for item in summaries), default=0.0),
            "malicious": bool(malicious),
            "suspicious": bool(suspicious),
            "mode": next(iter(modes)) if len(modes) == 1 else ("MIXED" if modes else "UNAVAILABLE"),
            "is_mock": any(item["is_mock"] for item in summaries),
            "conflict": any(item["conflict"] for item in summaries),
        }


def threat_intel_status() -> dict[str, Any]:
    providers = make_providers()
    return {
        "enabled": bool(threat_intel_settings().get("enabled", True)),
        "live_configured": any(providers[name].configured for name in ("virustotal", "abuseipdb")),
        "providers": {
            "virustotal": "configured" if providers["virustotal"].configured else "not_configured",
            "abuseipdb": "configured" if providers["abuseipdb"].configured else "not_configured",
            "mock": "available",
        },
        "mode": "LIVE" if any(providers[name].configured for name in ("virustotal", "abuseipdb")) else "DEMO_MOCK",
    }
