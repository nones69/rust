"""Main async Discrambler client."""

import asyncio
import ipaddress
from collections.abc import Sequence
from typing import Any, Optional

from .config import Config
from .models import IPResult, SubnetSummary
from .providers.geolocation import GeolocationProvider, IPWhoisGeoProvider, MaxMindProvider
from .providers.threat_intel import (
    AbuseIPDBProvider,
    ShodanProvider,
    ThreatIntelProvider,
    VirusTotalProvider,
)
from .providers.whois_rdap import WhoisRdapProvider
from .reverse_dns import reverse_dns
from .subnet import analyze_subnet


class Discrambler:
    """High-level client for IP enrichment and subnet analysis."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrency: int = 50,
        config: Optional[Config] = None,
        geo_provider: Optional[GeolocationProvider] = None,
    ):
        self.config = config or Config.from_env()
        self.config.request_timeout = timeout
        self.config.max_concurrency = max_concurrency
        self.geo = geo_provider or self._default_geo_provider()
        self.whois = WhoisRdapProvider(self.config)
        self.threat_providers: list[ThreatIntelProvider] = self._default_threat_providers()
        self._max_concurrency = max_concurrency
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _default_geo_provider(self) -> GeolocationProvider:
        if self.config.maxmind_db_path:
            return MaxMindProvider(self.config)
        return IPWhoisGeoProvider(self.config)

    def _default_threat_providers(self) -> list[ThreatIntelProvider]:
        providers: list[ThreatIntelProvider] = []
        if self.config.abuseipdb_api_key:
            providers.append(AbuseIPDBProvider(self.config))
        if self.config.virustotal_api_key:
            providers.append(VirusTotalProvider(self.config))
        if self.config.shodan_api_key:
            providers.append(ShodanProvider(self.config))
        return providers

    async def lookup(self, ip: str, include_rdns: bool = True) -> IPResult:
        """Enrich a single IP address."""
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            result = IPResult(ip=ip, errors=["invalid IP address"])
            return result

        result = IPResult(ip=ip, version=version)
        # Lazily create semaphore on first use to avoid requiring a running event loop
        # at construction time (fixes Python 3.9 compatibility). This is safe because
        # asyncio's cooperative model guarantees no other coroutine runs between the
        # None check and the assignment (there is no await point between them).
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrency)
        async with self._semaphore:
            geo_task = asyncio.create_task(self.geo.lookup(ip))
            rdns_task = asyncio.create_task(reverse_dns(ip, self.config)) if include_rdns else None
            threat_tasks = [asyncio.create_task(p.lookup(ip)) for p in self.threat_providers]

            geo = await geo_task
            if "error" in geo:
                result.errors.append(f"geo: {geo['error']}")
            else:
                result.country = geo.get("country")
                result.country_code = geo.get("country_code")
                result.region = geo.get("region")
                result.city = geo.get("city")
                result.latitude = geo.get("latitude")
                result.longitude = geo.get("longitude")
                result.asn = geo.get("asn")
                result.org = geo.get("org")
                result.isp = geo.get("isp")

            if rdns_task:
                result.reverse_dns = await rdns_task

            whois = await asyncio.get_event_loop().run_in_executor(None, self.whois.lookup, ip)
            if "error" in whois:
                result.errors.append(f"whois: {whois['error']}")
            else:
                result.whois = whois
                if not result.asn and whois.get("asn"):
                    result.asn = whois["asn"]
                if not result.org and whois.get("org"):
                    result.org = whois["org"]

            reports: list[dict[str, Any]] = []
            for task in asyncio.as_completed(threat_tasks):
                report = await task
                if "error" not in report:
                    reports.append(report)
                    result.threat_score = max(result.threat_score, report.get("score", 0))
                    result.abuse_confidence = max(
                        result.abuse_confidence, report.get("confidence", 0)
                    )
            result.threat_reports = reports

        return result

    async def lookup_batch(
        self, ips: Sequence[str], include_rdns: bool = True
    ) -> list[IPResult]:
        """Enrich many IPs concurrently."""
        tasks = [self.lookup(ip, include_rdns=include_rdns) for ip in ips]
        return await asyncio.gather(*tasks)

    def analyze_subnet(self, cidr: str, expand: bool = False, limit: int = 256) -> SubnetSummary:
        """Parse and summarize a CIDR block."""
        return analyze_subnet(cidr, expand=expand, limit=limit)

    def lookup_sync(self, ip: str, include_rdns: bool = True) -> IPResult:
        """Synchronous wrapper for single IP lookup."""
        return asyncio.run(self.lookup(ip, include_rdns=include_rdns))

    def lookup_batch_sync(
        self, ips: Sequence[str], include_rdns: bool = True
    ) -> list[IPResult]:
        """Synchronous wrapper for batch IP lookup."""
        return asyncio.run(self.lookup_batch(ips, include_rdns=include_rdns))
