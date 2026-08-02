from __future__ import annotations

import time

from app.blocklists.registry import BlocklistRegistry, _count_entries
from app.core.models import BlocklistHit, BlocklistReport


class BlocklistChecker:
    """Pure in-memory scanner. No I/O - all data is in the registry snapshot."""

    def __init__(self, registry: BlocklistRegistry, *, enabled: bool = True) -> None:
        self.registry = registry
        self.enabled = enabled

    async def check_ip(self, ip: str) -> BlocklistReport:
        return await self.check(ip=ip, domain=None)

    async def check_domain(self, domain: str) -> BlocklistReport:
        return await self.check(ip=None, domain=domain)

    async def check(
        self, *, ip: str | None = None, domain: str | None = None
    ) -> BlocklistReport:
        hits: list[BlocklistHit] = []
        source_counts: dict[str, int] = {}
        refreshed_at: dict[str, float] = {}
        checked_ips: list[str] = []
        checked_domain: str | None = None
        now = time.time()

        if not self.enabled:
            return BlocklistReport(
                hits=[], checked_at=now, source_counts={}, refreshed_at={},
                checked_ips=[], checked_domain=None,
            )

        for source in self.registry.enabled_sources():
            data, last_refreshed, _err = self.registry.snapshot(source.source_id)
            source_counts[source.source_id] = (
                _count_entries(data) if data is not None else 0
            )
            if last_refreshed is not None:
                refreshed_at[source.source_id] = last_refreshed
            if data is None:
                continue

            if ip is not None and source.kind in ("ip", "ip+domain"):
                detail = source.matches_ip(ip, data)
                if detail is not None:
                    hits.append(BlocklistHit(
                        source_id=source.source_id,
                        category=source.category,
                        severity=source.severity,
                        detail=detail,
                        matched_value=ip,
                    ))

            if domain is not None and source.kind in ("domain", "ip+domain"):
                matched = source.matches_domain(domain, data)
                if matched is not None:
                    hits.append(BlocklistHit(
                        source_id=source.source_id,
                        category=source.category,
                        severity=source.severity,
                        detail=matched,
                        matched_value=domain,
                    ))

        if ip is not None:
            checked_ips = [ip]
        if domain is not None:
            checked_domain = domain

        return BlocklistReport(
            hits=hits,
            checked_at=now,
            source_counts=source_counts,
            refreshed_at=refreshed_at,
            checked_ips=checked_ips,
            checked_domain=checked_domain,
        )
