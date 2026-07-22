from pathlib import Path
from types import SimpleNamespace

import pytest

from app.providers.ip2location import UNAVAILABLE, Ip2LocationProvider

DATA = Path(__file__).resolve().parents[2] / "data"


class FakeReader:
    def __init__(self, record=None, exc=None):
        self._record = record
        self._exc = exc

    def get_all(self, ip):
        if self._exc:
            raise self._exc
        return self._record


# Mirrors the real library: lat/lon are strings; unsupported fields are sentinels.
DB11_RECORD = SimpleNamespace(
    country_short="US",
    country_long="United States of America",
    region="California",
    city="Mountain View",
    zipcode="94035",
    latitude="37.386051",
    longitude="-122.083847",
    timezone="-07:00",
    isp=UNAVAILABLE,
)


@pytest.mark.asyncio
async def test_ip2location_maps_db11_fields():
    p = Ip2LocationProvider(db_path=Path("/nonexistent"), reader=FakeReader(DB11_RECORD))
    r = await p.lookup("8.8.8.8")
    assert r.error is None
    assert r.provider_id == "ip2location"
    assert r.country == "United States of America"
    assert r.country_code == "US"
    assert r.region == "California"
    assert r.city == "Mountain View"
    assert r.postal == "94035"
    assert r.latitude == pytest.approx(37.386051)
    assert r.longitude == pytest.approx(-122.083847)
    assert r.timezone == "-07:00"
    assert r.isp is None  # sentinel normalized


@pytest.mark.asyncio
async def test_ip2location_missing_db(tmp_path):
    p = Ip2LocationProvider(db_path=tmp_path / "missing.BIN")
    assert not p.available
    r = await p.lookup("8.8.8.8")
    assert r.error == "ip2location database not loaded"


@pytest.mark.asyncio
async def test_ip2location_lookup_exception():
    p = Ip2LocationProvider(
        db_path=Path("/nonexistent"), reader=FakeReader(exc=ValueError("boom"))
    )
    r = await p.lookup("8.8.8.8")
    assert r.error == "boom"


def _bin_path() -> Path | None:
    candidates = sorted(DATA.glob("IP2LOCATION*.BIN"))
    return candidates[0] if candidates else None


@pytest.mark.skipif(_bin_path() is None, reason="IP2Location BIN missing")
@pytest.mark.asyncio
async def test_ip2location_real_db():
    p = Ip2LocationProvider(db_path=_bin_path())
    assert p.available
    r = await p.lookup("8.8.8.8")
    assert r.error is None
    assert r.country_code == "US"
