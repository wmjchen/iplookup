from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import Any, Literal, Protocol, runtime_checkable
import urllib.parse

import httpx


@dataclass
class FetchResult:
    data: bytes
    etag: str | None = None
    last_modified: str | None = None


@dataclass
class IpNetsetData:
    ips_v4: set[IPv4Address] = field(default_factory=set)
    nets_v4: list[IPv4Network] = field(default_factory=list)
    ips_v6: set[IPv6Address] = field(default_factory=set)
    nets_v6: list[IPv6Network] = field(default_factory=list)
    details: dict[Any, str] = field(default_factory=dict)


@dataclass
class HostsData:
    domains: set[str] = field(default_factory=set)


@runtime_checkable
class BlocklistSource(Protocol):
    source_id: str
    category: str
    severity: int
    kind: Literal["ip", "domain", "ip+domain"]
    refresh_ttl: int
    url: str
    homepage: str
    lookup_url: str | None

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult: ...
    def parse(self, raw: bytes) -> Any: ...
    def matches_ip(self, ip: str, data: Any) -> str | None: ...
    def matches_domain(self, domain: str, data: Any) -> str | None: ...
    def lookup_url_for(self, value: str) -> str | None: ...


class IpNetsetSource:
    """Base class for sources with one IP or CIDR per line, '#' comments."""

    source_id: str = ""
    category: str = ""
    severity: int = 0
    kind: Literal["ip", "domain", "ip+domain"] = "ip"
    refresh_ttl: int = 3600
    url: str = ""
    homepage: str = ""
    lookup_url: str | None = None

    def lookup_url_for(self, value: str) -> str | None:
        if not self.lookup_url:
            return None
        return self.lookup_url.replace("{value}", urllib.parse.quote(value, safe=""))

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult:
        resp = await client.get(self.url)
        resp.raise_for_status()
        return FetchResult(
            data=resp.content,
            etag=resp.headers.get("etag"),
            last_modified=resp.headers.get("last-modified"),
        )

    def parse(self, raw: bytes) -> IpNetsetData:
        data = IpNetsetData()
        text = raw.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split("#", 1)[0].strip()
            if not token:
                continue
            try:
                if "/" in token and "." in token:
                    data.nets_v4.append(IPv4Network(token, strict=False))
                elif "/" in token and ":" in token:
                    data.nets_v6.append(IPv6Network(token, strict=False))
                elif ":" in token:
                    data.ips_v6.add(IPv6Address(token))
                else:
                    data.ips_v4.add(IPv4Address(token))
            except ValueError:
                continue
        data.nets_v4.sort(key=lambda n: int(n.network_address))
        data.nets_v6.sort(key=lambda n: int(n.network_address))
        return data

    def matches_ip(self, ip: str, data: IpNetsetData) -> str | None:
        try:
            addr = ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, IPv4Address):
            if addr in data.ips_v4:
                return data.details.get(addr, str(addr))
            for net in data.nets_v4:
                if addr in net:
                    return data.details.get(net, str(net))
        elif isinstance(addr, IPv6Address):
            if addr in data.ips_v6:
                return data.details.get(addr, str(addr))
            for net in data.nets_v6:
                if addr in net:
                    return data.details.get(net, str(net))
        return None

    def matches_domain(self, domain: str, data: IpNetsetData) -> str | None:
        return None  # IP-only source


class HostsFileSource:
    """Base class for sources in /etc/hosts format."""

    source_id: str = ""
    category: str = ""
    severity: int = 0
    kind: Literal["ip", "domain", "ip+domain"] = "domain"
    refresh_ttl: int = 86400
    url: str = ""
    homepage: str = ""
    lookup_url: str | None = None

    def lookup_url_for(self, value: str) -> str | None:
        if not self.lookup_url:
            return None
        return self.lookup_url.replace("{value}", urllib.parse.quote(value, safe=""))

    async def fetch(self, client: httpx.AsyncClient) -> FetchResult:
        resp = await client.get(self.url)
        resp.raise_for_status()
        return FetchResult(
            data=resp.content,
            etag=resp.headers.get("etag"),
            last_modified=resp.headers.get("last-modified"),
        )

    def parse(self, raw: bytes) -> HostsData:
        data = HostsData()
        text = raw.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            for host in parts[1:]:
                host = host.strip().lower()
                if host:
                    data.domains.add(host)
        return data

    def matches_domain(self, domain: str, data: HostsData) -> str | None:
        d = domain.strip().lower()
        if not d:
            return None
        if d in data.domains:
            return d
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in data.domains:
                return parent
        return None

    def matches_ip(self, ip: str, data: HostsData) -> str | None:
        return None  # Domain-only source
