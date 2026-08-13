import httpx
import pytest
import respx

from app.blocklists.sources.knockknock import (
    KnockKnockMonthSource, KnockKnockYearSource,
)


@pytest.mark.asyncio
@respx.mock
async def test_knockknock_year_parse_single_ips():
    body = "1.2.3.4\n5.6.7.8\n"
    respx.get("https://knock-knock.net/static/ip-blocklist-year.txt").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = KnockKnockYearSource()
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
        assert src.refresh_ttl == 3600
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_knockknock_month_parse_single_ips():
    body = "9.9.9.9\n8.8.8.8\n"
    respx.get("https://knock-knock.net/static/ip-blocklist-month.txt").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = KnockKnockMonthSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("9.9.9.9") in data.ips_v4
        assert IPv4Address("8.8.8.8") in data.ips_v4
        assert src.matches_ip("9.9.9.9", data) == "9.9.9.9"
        assert src.severity == 12
        assert src.category == "attacker"
        assert src.refresh_ttl == 3600
    finally:
        await client.aclose()


def test_knockknock_source_ids_distinct():
    year = KnockKnockYearSource()
    month = KnockKnockMonthSource()
    assert year.source_id == "knockknock_year"
    assert month.source_id == "knockknock_month"
    assert year.source_id != month.source_id
    assert year.url != month.url
    assert year.homepage == "https://knock-knock.net/blocklist"
    assert month.homepage == "https://knock-knock.net/blocklist"
