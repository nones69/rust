"""WHOIS / RDAP provider backend."""

from typing import Any

from ipwhois import IPWhois  # type: ignore

from ..config import Config


class WhoisRdapProvider:
    """Lookup ASN and org data via ipwhois (RDAP)."""

    def __init__(self, config: Config):
        self.config = config

    def lookup(self, ip: str) -> dict[str, Any]:
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            asn = result.get("asn")
            asn_description = result.get("asn_description")
            entities = result.get("entities", [])
            return {
                "asn": f"AS{asn}" if asn and not str(asn).upper().startswith("AS") else asn,
                "org": asn_description,
                "entities": entities,
                "network": result.get("network", {}),
            }
        except Exception as exc:  # pragma: no cover - tolerant
            return {"error": str(exc)}
