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
    listing = '<a href="2026-07-19-12-00-00-consensus">2026-07-19-12-00-00-consensus</a>'
    consensus = """network-status-version 3
vote-status consensus
valid-after 2026-07-19T12:00:00
r Unnamed ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef 2026-07-19T11:00:00 1.2.3.4 9001 9030
s Exit Fast Running V2Dir Valid
r AnotherName +abcdefghijklmnopqrstuvwxyz0123456789ABCD 2026-07-19T11:00:00 5.6.7.8 9001 9030
s Fast Guard Running V2Dir Valid
"""
    respx.get("https://collector.torproject.org/recent/relay-descriptors/consensuses/").mock(
        return_value=httpx.Response(200, content=listing.encode())
    )
    respx.get("https://collector.torproject.org/recent/relay-descriptors/consensuses/2026-07-19-12-00-00-consensus").mock(
        return_value=httpx.Response(200, content=consensus.encode())
    )
    src = TorConsensusSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        from ipaddress import IPv4Address
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("5.6.7.8") in data.ips_v4
        match = src.matches_ip("1.2.3.4", data)
        assert match is not None
        assert "Unnamed" in match
        match2 = src.matches_ip("5.6.7.8", data)
        assert match2 is not None
        assert "AnotherName" in match2
    finally:
        await client.aclose()
