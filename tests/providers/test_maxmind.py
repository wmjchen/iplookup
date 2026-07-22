from pathlib import Path

import pytest

from app.providers.hosting_asn import HostingAsnIndex
from app.providers.maxmind import MaxMindProvider

DATA = Path(__file__).resolve().parents[2] / "data"
CITY = DATA / "GeoLite2-City.mmdb"
ASN = DATA / "GeoLite2-ASN.mmdb"


@pytest.mark.skipif(not CITY.exists(), reason="GeoLite2-City.mmdb missing")
@pytest.mark.asyncio
async def test_maxmind_lookup_google_dns():
    hosting = HostingAsnIndex(asns={15169})
    provider = MaxMindProvider(city_db=CITY, asn_db=ASN, hosting_check=hosting)
    try:
        result = await provider.lookup("8.8.8.8")
        assert result.error is None
        assert result.provider_id == "maxmind"
        assert result.country_code in {"US", None} or result.country
        assert result.asn is not None
        assert result.asn.startswith("AS")
        assert result.is_hosting is True
    finally:
        provider.close()


@pytest.mark.asyncio
async def test_maxmind_missing_db(tmp_path: Path):
    provider = MaxMindProvider(city_db=tmp_path / "missing.mmdb")
    result = await provider.lookup("8.8.8.8")
    assert result.error is not None
