from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.blocklists.source import BlocklistSource
from app.blocklists.sources import all_sources, default_source_ids


@dataclass
class RefreshResult:
    source_id: str
    refreshed: bool
    entries: int
    last_refreshed: float | None
    last_error: str | None


def _count_entries(data: Any) -> int:
    """Best-effort count of entries in a parsed SourceData object."""
    if hasattr(data, "ips_v4") and hasattr(data, "ips_v6"):
        return (
            len(data.ips_v4) + len(data.ips_v6)
            + len(getattr(data, "nets_v4", [])) + len(getattr(data, "nets_v6", []))
        )
    if hasattr(data, "domains"):
        return len(data.domains)
    return 0


class BlocklistRegistry:
    """Holds compiled source data + per-source background refresh tasks."""

    def __init__(
        self,
        *,
        data_dir: Path,
        sources: list[BlocklistSource] | None = None,
        extra_source_ids: list[str] | None = None,
        user_agent: str = "iplookup/0.1 (blocklist-lookup)",
        offline_mode: bool = False,
        fetch_timeout: float = 30.0,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.user_agent = user_agent
        self.offline_mode = offline_mode
        self.fetch_timeout = fetch_timeout

        if sources is not None:
            self._sources: list[BlocklistSource] = list(sources)
        else:
            all_srcs = all_sources()
            by_id = {s.source_id: s for s in all_srcs}
            enabled_ids = set(default_source_ids())
            if extra_source_ids:
                enabled_ids.update(extra_source_ids)
            self._sources = [by_id[sid] for sid in enabled_ids if sid in by_id]
        self._data: dict[str, Any] = {}
        self._last_refreshed: dict[str, float] = {}
        self._last_error: dict[str, str | None] = {}
        self._refresh_tasks: list[asyncio.Task] = []
        self._client: httpx.AsyncClient | None = None

    def enabled_sources(self) -> list[BlocklistSource]:
        return list(self._sources)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.fetch_timeout,
                headers={"User-Agent": self.user_agent},
                follow_redirects=True,
            )
        return self._client

    async def _fetch_one(
        self, source: BlocklistSource
    ) -> tuple[BlocklistSource, Any, str | None]:
        try:
            client = await self._get_client()
            result = await source.fetch(client)
            data = source.parse(result.data)
            await self._write_cache(source.source_id, result)
            return source, data, None
        except Exception as exc:  # noqa: BLE001
            return source, None, str(exc)

    async def _write_cache(self, source_id: str, fetch_result: Any) -> None:
        try:
            cache_path = self.data_dir / f"{source_id}.cache"
            meta_path = self.data_dir / f"{source_id}.meta"
            cache_path.write_bytes(fetch_result.data)
            meta = {
                "fetched_at": time.time(),
                "etag": fetch_result.etag,
                "last_modified": fetch_result.last_modified,
                "content_length": len(fetch_result.data),
            }
            meta_path.write_text(json.dumps(meta))
        except OSError:
            pass  # cache write is best-effort

    async def load_all(self) -> None:
        """Parallel first-fetch. Swallow per-source errors, keep going."""
        if self.offline_mode:
            return  # no fetches; sources stay at 0 entries
        results = await asyncio.gather(
            *[self._fetch_one(s) for s in self._sources], return_exceptions=False
        )
        for source, data, err in results:
            sid = source.source_id
            if data is not None:
                self._data[sid] = data
                self._last_refreshed[sid] = time.time()
                self._last_error[sid] = None
            else:
                self._last_error[sid] = err
                cache_path = self.data_dir / f"{sid}.cache"
                if cache_path.exists():
                    try:
                        cached_raw = cache_path.read_bytes()
                        self._data[sid] = source.parse(cached_raw)
                    except Exception:  # noqa: BLE001
                        self._data[sid] = None

    async def load_disk_cache(self) -> None:
        """Load all sources from their disk cache files. No network I/O.

        Called unconditionally on startup when enable_blocklists=True, so cached
        data is available immediately even when refresh_on_startup=False or
        offline_mode=True.
        """
        for source in self._sources:
            sid = source.source_id
            cache_path = self.data_dir / f"{sid}.cache"
            if not cache_path.exists():
                continue
            try:
                cached_raw = cache_path.read_bytes()
                self._data[sid] = source.parse(cached_raw)
            except Exception as exc:  # noqa: BLE001
                self._last_error[sid] = str(exc)
                self._data[sid] = None

    async def refresh_source(self, source_id: str) -> RefreshResult:
        source = next((s for s in self._sources if s.source_id == source_id), None)
        if source is None:
            return RefreshResult(
                source_id=source_id, refreshed=False, entries=0,
                last_refreshed=None, last_error="unknown source_id",
            )
        _, data, err = await self._fetch_one(source)
        if data is not None:
            self._data[source_id] = data
            self._last_refreshed[source_id] = time.time()
            self._last_error[source_id] = None
            return RefreshResult(
                source_id=source_id, refreshed=True, entries=_count_entries(data),
                last_refreshed=self._last_refreshed[source_id], last_error=None,
            )
        self._last_error[source_id] = err
        return RefreshResult(
            source_id=source_id, refreshed=False, entries=0,
            last_refreshed=self._last_refreshed.get(source_id), last_error=err,
        )

    async def _refresh_loop(self, source: BlocklistSource) -> None:
        try:
            while True:
                await asyncio.sleep(max(1, source.refresh_ttl))
                await self.refresh_source(source.source_id)
        except asyncio.CancelledError:
            return

    async def start_refresh_tasks(self) -> None:
        if self._refresh_tasks or self.offline_mode:
            return
        for s in self._sources:
            self._refresh_tasks.append(asyncio.create_task(self._refresh_loop(s)))

    async def stop_refresh_tasks(self) -> None:
        for task in self._refresh_tasks:
            task.cancel()
        for task in self._refresh_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._refresh_tasks = []
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def snapshot(self, source_id: str) -> tuple[Any, float | None, str | None]:
        return (
            self._data.get(source_id),
            self._last_refreshed.get(source_id),
            self._last_error.get(source_id),
        )

    def summary(self) -> list[dict]:
        out = []
        now = time.time()
        for s in self._sources:
            data, refreshed, err = self.snapshot(s.source_id)
            entries = _count_entries(data) if data is not None else 0
            next_refresh = None
            if refreshed is not None:
                next_refresh = max(0, int(s.refresh_ttl - (now - refreshed)))
            out.append({
                "source_id": s.source_id,
                "category": s.category,
                "severity": s.severity,
                "kind": s.kind,
                "entries": entries,
                "last_refreshed": refreshed,
                "next_refresh_in": next_refresh,
                "last_error": err,
                "homepage": s.homepage,
                "lookup_url": s.lookup_url,
            })
        return out

    def total_entries(self) -> int:
        return sum(
            _count_entries(data) if data is not None else 0
            for data in self._data.values()
        )
