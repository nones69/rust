"""Client tests with mocked providers."""

import pytest

from ip_discrambler.client import Discrambler
from ip_discrambler.config import Config
from ip_discrambler.models import IPResult
from ip_discrambler.providers.geolocation import GeolocationProvider


class FakeGeo(GeolocationProvider):
    async def lookup(self, ip: str):
        return {
            "country": "United States",
            "country_code": "US",
            "city": "Example City",
            "asn": "AS15169",
            "org": "Example Org",
        }


@pytest.fixture
def client():
    cfg = Config()
    return Discrambler(config=cfg, geo_provider=FakeGeo(cfg), max_concurrency=2)


def test_lookup_public_ip(client):
    result = client.lookup_sync("8.8.8.8")
    assert isinstance(result, IPResult)
    assert result.ip == "8.8.8.8"
    assert result.country == "United States"
    assert result.country_code == "US"


def test_lookup_invalid_ip(client):
    result = client.lookup_sync("not-an-ip")
    assert "invalid IP address" in result.errors


def test_analyze_subnet(client):
    summary = client.analyze_subnet("10.0.0.0/8", expand=False)
    assert summary.total_hosts == 16_777_216
    assert summary.is_private is True
