import asyncio
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from app.blocklists.registry import BlocklistRegistry, RefreshResult
from app.blocklists.source import FetchResult, IpNetsetData


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "blocklists"
    d.mkdir()
    return d


class _FakeSource:
    """Minimal in-memory source for registry tests (avoids network)."""

    kind = "ip"
    category = "test"
    url = "http://example.invalid/"
    homepage = ""
    lookup_url = None

    def __init__(self, source_id: str, body: bytes, severity: int = 10,
                 refresh_ttl: int = 3600) -> None:
        self.source_id = source_id
        self.url = f"http://example.invalid/{source_id}"
        self.body = body
        self.severity = severity
        self.refresh_ttl = refresh_ttl

    async def fetch(self, client):
        return FetchResult(data=self.body)

    def parse(self, raw: bytes) -> IpNetsetData:
        d = IpNetsetData()
        for line in raw.decode().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                d.ips_v4.add(IPv4Address(line))
            except ValueError:
                continue
        return d

    def matches_ip(self, ip: str, data: IpNetsetData):
        try:
            addr = IPv4Address(ip)
        except ValueError:
            return None
        return str(addr) if addr in data.ips_v4 else None

    def matches_domain(self, domain: str, data):
        return None


@pytest.mark.asyncio
async def test_registry_load_all_populates_snapshot(tmp_data_dir):
    src = _FakeSource("test_a", b"1.2.3.4\n5.6.7.8\n")
    reg = BlocklistRegistry(data_dir=tmp_data_dir, sources=[src])
    await reg.load_all()
    data, refreshed_at, err = reg.snapshot("test_a")
    assert data is not None
    assert refreshed_at is not None
    assert err is None
    assert reg.total_entries() == 2


@pytest.mark.asyncio
async def test_registry_load_all_isolates_per_source_failures(tmp_data_dir):
    class BoomSource(_FakeSource):
        async def fetch(self, client):
            raise RuntimeError("upstream dead")
    reg = BlocklistRegistry(
        data_dir=tmp_data_dir,
        sources=[_FakeSource("ok", b"1.1.1.1\n"), BoomSource("boom", b"")],
    )
    await reg.load_all()
    data_ok, _, err_ok = reg.snapshot("ok")
    data_boom, _, err_boom = reg.snapshot("boom")
    assert data_ok is not None
    assert err_ok is None
    assert data_boom is None
    assert err_boom == "upstream dead"


@pytest.mark.asyncio
async def test_registry_summary_structure(tmp_data_dir):
    src = _FakeSource("test_a", b"1.1.1.1\n2.2.2.2\n")
    reg = BlocklistRegistry(data_dir=tmp_data_dir, sources=[src])
    await reg.load_all()
    summary = reg.summary()
    assert len(summary) == 1
    s = summary[0]
    assert s["source_id"] == "test_a"
    assert s["entries"] == 2
    assert s["last_error"] is None
    assert "next_refresh_in" in s


@pytest.mark.asyncio
async def test_registry_summary_includes_homepage_and_lookup_url(tmp_data_dir):
    class LinkSource(_FakeSource):
        homepage = "https://example.invalid/"
        lookup_url = "https://example.invalid/q?ip={value}"
    reg = BlocklistRegistry(
        data_dir=tmp_data_dir, sources=[LinkSource("linked", b"1.1.1.1\n")],
    )
    await reg.load_all()
    s = reg.summary()[0]
    assert s["homepage"] == "https://example.invalid/"
    assert s["lookup_url"] == "https://example.invalid/q?ip={value}"


@pytest.mark.asyncio
async def test_registry_refresh_source_returns_result(tmp_data_dir):
    src = _FakeSource("test_a", b"1.1.1.1\n")
    reg = BlocklistRegistry(data_dir=tmp_data_dir, sources=[src])
    await reg.load_all()
    src.body = b"1.1.1.1\n9.9.9.9\n"
    result = await reg.refresh_source("test_a")
    assert isinstance(result, RefreshResult)
    assert result.refreshed is True
    assert result.entries == 2
    data, _, _ = reg.snapshot("test_a")
    assert IPv4Address("9.9.9.9") in data.ips_v4


@pytest.mark.asyncio
async def test_registry_start_stop_refresh_tasks(tmp_data_dir):
    src = _FakeSource("test_a", b"1.1.1.1\n", refresh_ttl=1)
    reg = BlocklistRegistry(data_dir=tmp_data_dir, sources=[src])
    await reg.load_all()
    await reg.start_refresh_tasks()
    await asyncio.sleep(0.05)
    await reg.stop_refresh_tasks()


@pytest.mark.asyncio
async def test_registry_load_disk_cache_loads_existing_files_without_fetch(tmp_data_dir):
    # Empty body so any accidental fetch() call contributes nothing - we want to
    # prove the data came from the cache file, not from fetch().
    src = _FakeSource("cached_src", b"")
    cache_path = tmp_data_dir / "cached_src.cache"
    cache_path.write_bytes(b"1.1.1.1\n2.2.2.2\n")
    reg = BlocklistRegistry(data_dir=tmp_data_dir, sources=[src])
    # Do NOT call load_all() - only load_disk_cache (no network I/O).
    await reg.load_disk_cache()
    data, refreshed_at, err = reg.snapshot("cached_src")
    assert data is not None
    assert IPv4Address("1.1.1.1") in data.ips_v4
    assert IPv4Address("2.2.2.2") in data.ips_v4
    # Cache-only load must not mark the source as freshly refreshed.
    assert refreshed_at is None
    assert err is None
