from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv6Address

import httpx

from app.blocklists.source import FetchResult, IpNetsetData, IpNetsetSource

_ONIONOO_SUMMARY = "https://onionoo.torproject.org/summary?flag=Running"


class TorBulkExitSource(IpNetsetSource):
    source_id = "tor_bulk_exit"
    category = "tor_exit"
    severity = 18
    refresh_ttl = 3600
    url = "https://check.torproject.org/torbulkexitlist"


class TorExitAddressesSource(IpNetsetSource):
    source_id = "tor_exit_addresses"
    category = "tor_exit"
    severity = 18
    refresh_ttl = 3600
    url = "https://check.torproject.org/exit-addresses"

    def parse(self, raw: bytes) -> IpNetsetData:
        data = IpNetsetData()
        text = raw.decode("utf-8", errors="replace")
        for line in text.splitlines():
            parts = line.split()
            for i, token in enumerate(parts):
                if token == "ExitAddress" and i + 1 < len(parts):
                    try:
                        data.ips_v4.add(IPv4Address(parts[i + 1]))
                    except ValueError:
                        continue
        return data


class TorConsensusSource(IpNetsetSource):
    source_id = "tor_consensus"
    category = "tor_relay"
    severity = 8
    refresh_ttl = 3600
    url = _ONIONOO_SUMMARY

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult:
        resp = await client.get(_ONIONOO_SUMMARY)
        resp.raise_for_status()
        return FetchResult(data=resp.content)

    def parse(self, raw: bytes) -> IpNetsetData:
        data = IpNetsetData()
        doc = json.loads(raw.decode("utf-8", errors="replace"))
        for relay in doc.get("relays", []):
            if not relay.get("r"):
                continue
            nickname = relay.get("n", "")
            for addr_str in relay.get("a", []):
                addr_str = addr_str.strip("[]")
                try:
                    if ":" in addr_str:
                        addr = IPv6Address(addr_str)
                        data.ips_v6.add(addr)
                    else:
                        addr = IPv4Address(addr_str)
                        data.ips_v4.add(addr)
                except ValueError:
                    continue
                data.details[addr] = f"relay:{nickname}"
        return data
