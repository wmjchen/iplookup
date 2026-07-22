import httpx
import pytest
import respx

from app.blocklists.sources.ipsum import IpsumSource


def test_ipsum_factory_source_ids():
    three = IpsumSource(level=3)
    five = IpsumSource(level=5)
    assert three.source_id == "ipsum_3"
    assert five.source_id == "ipsum_5"
    assert three.severity == 18
    assert five.severity == 22
    assert three.url == "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    assert five.url == "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"


@pytest.mark.asyncio
@respx.mock
async def test_ipsum_parse_ip_list():
    body = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
    respx.get("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = IpsumSource(level=3)
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("9.10.11.12") in data.ips_v4
        assert src.matches_ip("5.6.7.8", data) == "5.6.7.8"
        assert src.category == "attacker"
    finally:
        await client.aclose()


def test_ipsum_invalid_level():
    with pytest.raises(ValueError):
        IpsumSource(level=99)
