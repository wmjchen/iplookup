from pathlib import Path

import pytest

from app.providers.ip_index import IpIndexProvider

DATA = Path(__file__).resolve().parents[2] / "data"
DB = DATA / "ip-index.mmdb"


@pytest.mark.skipif(not DB.exists(), reason="ip-index.mmdb missing")
@pytest.mark.asyncio
async def test_ip_index_quad9_record():
    provider = IpIndexProvider(db_path=DB)
    try:
        assert provider.available
        result = await provider.lookup("9.9.9.9")
        assert result.error is None
        assert result.provider_id == "ip_index"
        assert result.asn == "AS19281"
        assert result.country_code == "US"
        # ip-index currently marks Quad9 hosting=0; still useful ASN/country row
        assert result.is_hosting is False
    finally:
        provider.close()


@pytest.mark.skipif(not DB.exists(), reason="ip-index.mmdb missing")
@pytest.mark.asyncio
async def test_ip_index_google_dns():
    provider = IpIndexProvider(db_path=DB)
    try:
        result = await provider.lookup("8.8.8.8")
        assert result.error is None
        assert result.is_hosting is True
        assert result.country_code is not None or result.country is not None
    finally:
        provider.close()


@pytest.mark.asyncio
async def test_ip_index_missing_db(tmp_path: Path):
    provider = IpIndexProvider(db_path=tmp_path / "missing.mmdb")
    result = await provider.lookup("8.8.8.8")
    assert result.error is not None
