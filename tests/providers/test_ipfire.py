from pathlib import Path

import pytest

from app.providers.ipfire import IpfireProvider

DATA = Path(__file__).resolve().parents[2] / "data"
LOC_DB = DATA / "location.db.xz"


class FakeLocDB:
    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc

    def lookup(self, ip):
        if self._exc:
            raise self._exc
        return self._result


@pytest.mark.asyncio
async def test_ipfire_maps_all_fields():
    db = FakeLocDB((("AU", "OC", "Australia"), 13335, "Cloudflare, Inc.", 4, 24))
    p = IpfireProvider(db_path=Path("/nonexistent"), db=db)
    r = await p.lookup("1.1.1.1")
    assert r.error is None
    assert r.provider_id == "ipfire"
    assert r.country == "Australia"
    assert r.country_code == "AU"
    assert r.asn == "AS13335"
    assert r.as_name == "Cloudflare, Inc."
    assert r.isp == "Cloudflare, Inc."
    assert r.org == "Cloudflare, Inc."
    assert r.flags == ["anycast"]
    assert r.is_proxy is None


@pytest.mark.asyncio
async def test_ipfire_anonymous_proxy_sets_is_proxy():
    db = FakeLocDB((("SE", "EU", "Sweden"), 198093, "DFRI", 1, 24))
    p = IpfireProvider(db_path=Path("/nonexistent"), db=db)
    r = await p.lookup("171.25.193.20")
    assert r.error is None
    assert r.is_proxy is True
    assert r.flags == ["anonymous_proxy"]


@pytest.mark.asyncio
async def test_ipfire_multiple_flags():
    db = FakeLocDB((("US", "NA", "United States"), 1, "X", 1 | 4 | 8, 24))
    p = IpfireProvider(db_path=Path("/nonexistent"), db=db)
    r = await p.lookup("6.6.6.6")
    assert r.flags == ["anonymous_proxy", "anycast", "hostile_network"]
    assert r.is_proxy is True


@pytest.mark.asyncio
async def test_ipfire_no_data():
    p = IpfireProvider(db_path=Path("/nonexistent"), db=FakeLocDB(None))
    r = await p.lookup("10.0.0.1")
    assert r.error == "no data"


@pytest.mark.asyncio
async def test_ipfire_missing_db(tmp_path):
    p = IpfireProvider(db_path=tmp_path / "missing.db.xz")
    assert not p.available
    r = await p.lookup("8.8.8.8")
    assert r.error == "ipfire database not loaded"


@pytest.mark.asyncio
async def test_ipfire_lookup_exception():
    p = IpfireProvider(db_path=Path("/nonexistent"), db=FakeLocDB(exc=ValueError("boom")))
    r = await p.lookup("8.8.8.8")
    assert r.error == "boom"


@pytest.mark.skipif(not LOC_DB.exists(), reason="location.db.xz missing")
@pytest.mark.asyncio
async def test_ipfire_real_db_anycast():
    p = IpfireProvider(db_path=LOC_DB)
    assert p.available
    r = await p.lookup("1.1.1.1")
    assert r.error is None
    assert r.asn == "AS13335"
    assert "anycast" in r.flags
