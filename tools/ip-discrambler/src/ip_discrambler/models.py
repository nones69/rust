"""Data models used throughout IP-Discrambler."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class IPResult:
    """Aggregated enrichment result for a single IP address."""

    ip: str
    version: int = 4
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    reverse_dns: Optional[str] = None
    threat_score: int = 0
    abuse_confidence: int = 0
    whois: Dict[str, Any] = field(default_factory=dict)
    threat_reports: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "version": self.version,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "org": self.org,
            "isp": self.isp,
            "reverse_dns": self.reverse_dns,
            "threat_score": self.threat_score,
            "abuse_confidence": self.abuse_confidence,
            "whois": self.whois,
            "threat_reports": self.threat_reports,
            "errors": self.errors,
        }


@dataclass
class ThreatReport:
    """Threat intelligence summary for an IP."""

    provider: str
    score: int = 0
    confidence: int = 0
    categories: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "score": self.score,
            "confidence": self.confidence,
            "categories": self.categories,
            "raw": self.raw,
        }


@dataclass
class SubnetSummary:
    """Summary of a parsed CIDR block."""

    cidr: str
    version: int = 4
    network_address: str = ""
    netmask: str = ""
    broadcast_address: Optional[str] = None
    total_hosts: int = 0
    usable_hosts: int = 0
    first_usable: Optional[str] = None
    last_usable: Optional[str] = None
    is_private: bool = False
    is_reserved: bool = False
    expanded: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cidr": self.cidr,
            "version": self.version,
            "network_address": self.network_address,
            "netmask": self.netmask,
            "broadcast_address": self.broadcast_address,
            "total_hosts": self.total_hosts,
            "usable_hosts": self.usable_hosts,
            "first_usable": self.first_usable,
            "last_usable": self.last_usable,
            "is_private": self.is_private,
            "is_reserved": self.is_reserved,
            "expanded": self.expanded,
        }
