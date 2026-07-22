from __future__ import annotations

import asyncio
import socket
from typing import Awaitable, Callable

from app.core.models import DnsRecords


async def resolve_domain(
    domain: str,
    *,
    resolver: Callable[[str], Awaitable[DnsRecords]] | None = None,
) -> DnsRecords:
    if resolver is not None:
        return await resolver(domain)

    def _lookup() -> DnsRecords:
        a: list[str] = []
        aaaa: list[str] = []
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror:
            return DnsRecords(domain=domain, a=[], aaaa=[])

        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                ip = sockaddr[0]
                if ip not in a:
                    a.append(ip)
            elif family == socket.AF_INET6:
                ip = sockaddr[0]
                if ip not in aaaa:
                    aaaa.append(ip)
        return DnsRecords(domain=domain, a=a, aaaa=aaaa)

    return await asyncio.to_thread(_lookup)
