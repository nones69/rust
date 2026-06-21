"""Reverse DNS (PTR) resolution helpers."""

import asyncio
import socket
from typing import Optional

from .config import Config


async def reverse_dns(ip: str, config: Config) -> Optional[str]:
    """Resolve a PTR record for an IP address asynchronously."""
    try:
        host, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip),
            timeout=config.reverse_dns_timeout,
        )
        return host
    except Exception:
        return None
