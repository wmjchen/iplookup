from __future__ import annotations

import asyncio
import socket
from typing import Callable, Awaitable


async def reverse_dns(
    ip: str,
    resolver: Callable[[str], Awaitable[str | None]] | None = None,
) -> str | None:
    if resolver is not None:
        return await resolver(ip)

    def _lookup() -> str | None:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return None

    return await asyncio.to_thread(_lookup)
