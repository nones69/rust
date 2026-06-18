"""Reverse DNS (PTR) resolution helpers."""

import asyncio
import socket
from typing import Optional

from .config import Config


async def reverse_dns(ip: str, config: Config) -> Optional[str]:
    """Resolve a PTR record for an IP address asynchronously."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=config.reverse_dns_timeout,
        )[0]
    except Exception:
        return None
