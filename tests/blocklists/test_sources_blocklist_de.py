import httpx
import pytest
import respx

from app.blocklists.sources.blocklist_de import BlocklistDeSource


@pytest.mark.asyncio
@respx.mock
async def test_blocklist_de_parse_single_ips():
    body = "1.2.3.4\n5.6.7.8\n"
    respx.get("https://lists.blocklist.de/lists/all.txt").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = BlocklistDeSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("5.6.7.8") in data.ips_v4
        assert src.matches_ip("1.2.3.4", data) == "1.2.3.4"
        assert src.severity == 12
        assert src.category == "attacker"
    finally:
        await client.aclose()
