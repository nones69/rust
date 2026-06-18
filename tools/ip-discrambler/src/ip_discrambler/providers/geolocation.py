"""Geolocation provider backends."""

import ipaddress
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import httpx

from ..config import Config


class GeolocationProvider(ABC):
    """Base class for IP geolocation lookups."""

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    async def lookup(self, ip: str) -> Dict[str, Any]:
        ...


class IPWhoisGeoProvider(GeolocationProvider):
    """Free geolocation lookup via ipwho.is public API."""

    async def lookup(self, ip: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                resp = await client.get(f"https://ipwho.is/{ip}")
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # pragma: no cover - network tolerant
            return {"error": str(exc)}

        if not data.get("success"):
            return {"error": data.get("message", "lookup failed")}

        return {
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": _format_asn(data.get("connection", {}).get("asn")),
            "org": data.get("connection", {}).get("org"),
            "isp": data.get("connection", {}).get("isp"),
        }


class MaxMindProvider(GeolocationProvider):
    """Offline MaxMind GeoLite2 lookup."""

    def __init__(self, config: Config):
        super().__init__(config)
        self._reader: Optional[Any] = None
        if config.maxmind_db_path:
            try:
                import geoip2.database  # type: ignore

                self._reader = geoip2.database.Reader(config.maxmind_db_path)
            except Exception as exc:  # pragma: no cover - optional dep
                self._reader = None
                self._error = str(exc)

    async def lookup(self, ip: str) -> Dict[str, Any]:
        if self._reader is None:
            return {"error": "MaxMind database not available"}
        try:
            city = self._reader.city(ip)
            return {
                "country": city.country.name,
                "country_code": city.country.iso_code,
                "region": city.subdivisions.most_specific.name,
                "city": city.city.name,
                "latitude": float(city.location.latitude) if city.location.latitude else None,
                "longitude": float(city.location.longitude) if city.location.longitude else None,
                "asn": None,
                "org": None,
                "isp": None,
            }
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}


def _format_asn(asn: Any) -> Optional[str]:
    if asn is None:
        return None
    return f"AS{asn}" if not str(asn).upper().startswith("AS") else str(asn)


def _is_public_ip(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
