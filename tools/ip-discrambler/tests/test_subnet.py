"""Subnet analysis tests."""

from ip_discrambler.subnet import analyze_subnet


def test_ipv4_subnet():
    s = analyze_subnet("192.168.1.0/24")
    assert s.total_hosts == 256
    assert s.usable_hosts == 254
    assert s.network_address == "192.168.1.0"
    assert s.is_private is True


def test_ipv4_expand():
    s = analyze_subnet("192.168.1.0/30", expand=True)
    assert s.expanded == ["192.168.1.1", "192.168.1.2"]


def test_ipv6_subnet():
    s = analyze_subnet("2001:db8::/32")
    assert s.version == 6
    assert s.is_private is False
