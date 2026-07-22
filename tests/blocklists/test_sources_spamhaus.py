import httpx
import pytest
import respx

from app.blocklists.sources.spamhaus import (
    SpamhausDropSource,
    SpamhausEdropSource,
    SpamhausDropv6Source,
)


@pytest.mark.asyncio
@respx.mock
async def test_spamhaus_drop_fetch_and_parse():
    body = """; Spamhaus DROP list
1.0.0.0/24 ; SBL1234
2.0.0.0/24 ; SBL5678
"""
    respx.get("https://www.spamhaus.org/drop/drop.txt").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = SpamhausDropSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Network
        assert IPv4Network("1.0.0.0/24") in data.nets_v4
        assert IPv4Network("2.0.0.0/24") in data.nets_v4
        assert src.matches_ip("1.0.0.5", data) == "1.0.0.0/24"
        assert src.matches_ip("3.0.0.1", data) is None
        assert src.severity == 25
        assert src.category == "hijacked_network"
    finally:
        await client.aclose()


def test_spamhaus_source_ids():
    assert SpamhausDropSource().source_id == "spamhaus_drop"
    assert SpamhausEdropSource().source_id == "spamhaus_edrop"
    assert SpamhausDropv6Source().source_id == "spamhaus_dropv6"
    assert SpamhausDropv6Source().severity == 25
