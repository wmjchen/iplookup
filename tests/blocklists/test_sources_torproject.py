import json

import httpx
import pytest
import respx

from app.blocklists.sources.torproject import (
    TorBulkExitSource, TorExitAddressesSource, TorConsensusSource,
)


def test_tor_source_ids_severities():
    assert TorBulkExitSource().source_id == "tor_bulk_exit"
    assert TorBulkExitSource().severity == 18
    assert TorBulkExitSource().category == "tor_exit"
    assert TorExitAddressesSource().source_id == "tor_exit_addresses"
    assert TorConsensusSource().source_id == "tor_consensus"
    assert TorConsensusSource().category == "tor_relay"
    assert TorConsensusSource().severity == 8


@pytest.mark.asyncio
@respx.mock
async def test_tor_bulk_exit_parse():
    body = "1.2.3.4\n5.6.7.8\n"
    respx.get("https://check.torproject.org/torbulkexitlist").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = TorBulkExitSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert src.matches_ip("5.6.7.8", data) == "5.6.7.8"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_tor_exit_addresses_parse():
    body = """ExitNode ABC123 Published 2026-07-19 12:00:00 LastStatus 2026-07-19 12:00:00 ExitAddress 1.2.3.4 2026-07-19 12:00:00
ExitNode DEF456 Published 2026-07-19 11:00:00 LastStatus 2026-07-19 12:00:00 ExitAddress 5.6.7.8 2026-07-19 11:30:00
"""
    respx.get("https://check.torproject.org/exit-addresses").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = TorExitAddressesSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("5.6.7.8") in data.ips_v4
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_tor_consensus_fetch_and_parse():
    body = {
        "version": "8.0",
        "relays_published": "2026-08-02 17:00:00",
        "relays": [
            {"n": "Unnamed", "f": "AAAA000000000000000000000000000000000001",
             "a": ["1.2.3.4"], "r": True},
            {"n": "AnotherName", "f": "BBBB000000000000000000000000000000000002",
             "a": ["5.6.7.8", "[2001:db8::1]"], "r": True},
        ],
    }
    respx.get("https://onionoo.torproject.org/summary?flag=Running").mock(
        return_value=httpx.Response(
            200, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
    )
    src = TorConsensusSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address, IPv6Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("5.6.7.8") in data.ips_v4
        assert IPv6Address("2001:db8::1") in data.ips_v6
        match = src.matches_ip("1.2.3.4", data)
        assert match is not None
        assert "Unnamed" in match
        match2 = src.matches_ip("5.6.7.8", data)
        assert match2 is not None
        assert "AnotherName" in match2
    finally:
        await client.aclose()
