"""Threat intelligence provider backends."""

from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..config import Config


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence lookups."""

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    async def lookup(self, ip: str) -> dict[str, Any]:
        ...


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB reputation lookup."""

    async def lookup(self, ip: str) -> dict[str, Any]:
        if not self.config.abuseipdb_api_key:
            return {"error": "ABUSEIPDB_API_KEY not configured"}
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.config.abuseipdb_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}
        return {
            "provider": "abuseipdb",
            "score": data.get("abuseConfidenceScore", 0),
            "confidence": data.get("abuseConfidenceScore", 0),
            "categories": data.get("usageType", []),
            "raw": data,
        }


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal IP reputation lookup."""

    async def lookup(self, ip: str) -> dict[str, Any]:
        if not self.config.virustotal_api_key:
            return {"error": "VIRUSTOTAL_API_KEY not configured"}
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.config.virustotal_api_key},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                last_analysis = attrs.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                total = sum(last_analysis.values()) or 1
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}
        score = int(((malicious + suspicious) / total) * 100)
        return {
            "provider": "virustotal",
            "score": score,
            "confidence": score,
            "categories": [],
            "raw": attrs,
        }


class ShodanProvider(ThreatIntelProvider):
    """Shodan host intelligence lookup."""

    async def lookup(self, ip: str) -> dict[str, Any]:
        if not self.config.shodan_api_key:
            return {"error": "SHODAN_API_KEY not configured"}
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": self.config.shodan_api_key},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}
        return {
            "provider": "shodan",
            "score": 0,
            "confidence": 0,
            "categories": data.get("tags", []),
            "raw": data,
        }
