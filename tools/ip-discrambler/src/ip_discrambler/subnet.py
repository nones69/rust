"""Subnet / CIDR analysis helpers."""

import ipaddress
from typing import List, Optional

from .models import SubnetSummary


RESERVED_NETWORKS_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def analyze_subnet(cidr: str, expand: bool = False, limit: int = 256) -> SubnetSummary:
    """Parse a CIDR block and return a structured summary."""
    network = ipaddress.ip_network(cidr, strict=False)
    version = network.version
    total = network.num_addresses
    if version == 4:
        if total <= 2:
            usable = total
        else:
            usable = total - 2
    else:
        usable = total

    first: Optional[str] = None
    last: Optional[str] = None
    broadcast: Optional[str] = None
    if version == 4:
        broadcast = str(network.broadcast_address)
        if usable > 0:
            first = str(network[1]) if total > 2 else str(network[0])
            last = str(network[-2]) if total > 2 else str(network[-1])
    else:
        first = str(network[0])
        last = str(network[-1])

    expanded: List[str] = []
    if expand and total <= limit:
        expanded = [str(host) for host in network.hosts()]

    is_private = network.is_private
    is_reserved = any(network.subnet_of(res) for res in RESERVED_NETWORKS_V4) if version == 4 else False

    return SubnetSummary(
        cidr=str(network),
        version=version,
        network_address=str(network.network_address),
        netmask=str(network.netmask),
        broadcast_address=broadcast,
        total_hosts=total,
        usable_hosts=usable,
        first_usable=first,
        last_usable=last,
        is_private=is_private,
        is_reserved=is_reserved,
        expanded=expanded,
    )
