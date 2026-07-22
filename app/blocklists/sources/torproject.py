from __future__ import annotations

import re
from ipaddress import IPv4Address

import httpx

from app.blocklists.source import FetchResult, IpNetsetData, IpNetsetSource

_CONSENSUS_BASE = "https://collector.torproject.org/recent/relay-descriptors/consensuses/"


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
    url = _CONSENSUS_BASE  # directory listing; fetch() handles two-step

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult:
        listing_resp = await client.get(_CONSENSUS_BASE)
        listing_resp.raise_for_status()
        link_pattern = re.compile(r'href="([^"/]+-consensus)"')
        candidates = link_pattern.findall(listing_resp.text)
        if not candidates:
            link_pattern2 = re.compile(r'href="(\d[^"]+)"')
            candidates = link_pattern2.findall(listing_resp.text)
        if not candidates:
            raise RuntimeError("no consensus files found in collector listing")
        latest = sorted(candidates)[-1]
        resp = await client.get(_CONSENSUS_BASE + latest)
        resp.raise_for_status()
        return FetchResult(data=resp.content)

    def parse(self, raw: bytes) -> IpNetsetData:
        data = IpNetsetData()
        text = raw.decode("utf-8", errors="replace")
        current_nickname: str | None = None
        for line in text.splitlines():
            if line.startswith("r "):
                parts = line.split()
                if len(parts) >= 6:
                    current_nickname = parts[1]
                    ip_str = parts[4]
                    try:
                        addr = IPv4Address(ip_str) if "." in ip_str else None
                    except ValueError:
                        addr = None
                    if addr is not None:
                        data.ips_v4.add(addr)
                        data.details[addr] = f"relay:{current_nickname}"
            elif line.startswith("s "):
                parts = line.split()
                current_flags = parts[1:]
                if current_nickname is not None and current_flags:
                    for addr, det in list(data.details.items()):
                        if det == f"relay:{current_nickname}":
                            data.details[addr] = (
                                f"relay:{current_nickname} flags:{' '.join(current_flags)}"
                            )
                            break
        return data
