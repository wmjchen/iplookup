from __future__ import annotations

import io
import json
import tarfile
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx

from app.blocklists.source import FetchResult, IpNetsetData, IpNetsetSource

_TARBALL_URL = "https://codeload.github.com/qdm12/gluetun-servers/tar.gz/refs/heads/main"


class GluetunVpnSource(IpNetsetSource):
    source_id = "gluetun_vpn"
    category = "vpn_endpoint"
    severity = 15
    refresh_ttl = 86400  # 24h
    url = _TARBALL_URL
    homepage = "https://github.com/qdm12/gluetun-servers"

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult:
        resp = await client.get(_TARBALL_URL)
        resp.raise_for_status()
        packed: list[dict[str, Any]] = []
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                name = member.name
                if not member.isfile() or not name.endswith(".json"):
                    continue
                if "/pkg/servers/" not in name:
                    continue
                provider_name = name.rsplit("/", 1)[-1].removesuffix(".json")
                f = tar.extractfile(member)
                if f is None:
                    continue
                try:
                    payload = json.loads(f.read())
                except (ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                packed.append(
                    {"provider": provider_name, "servers": payload.get("servers", [])}
                )
        return FetchResult(
            data=json.dumps(packed).encode(),
            etag=resp.headers.get("etag"),
            last_modified=resp.headers.get("last-modified"),
        )

    def parse(self, raw: bytes) -> IpNetsetData:
        data = IpNetsetData()
        try:
            packed = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return data
        for provider_blob in packed:
            provider = provider_blob.get("provider", "unknown")
            for entry in provider_blob.get("servers", []):
                hostname = entry.get("hostname") or ""
                ips: list[str] = entry.get("ips") or ([entry["ip"]] if entry.get("ip") else [])
                detail = f"VPN provider: {provider}"
                if hostname:
                    detail += f" (hostname: {hostname})"
                for ip_str in ips:
                    try:
                        if "." in ip_str:
                            addr = IPv4Address(ip_str)
                            data.ips_v4.add(addr)
                            data.details[addr] = detail
                        elif ":" in ip_str:
                            addr = IPv6Address(ip_str)
                            data.ips_v6.add(addr)
                            data.details[addr] = detail
                    except ValueError:
                        continue
        return data
