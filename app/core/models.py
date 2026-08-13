from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ProviderResult(BaseModel):
    provider_id: str
    ip: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    postal: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    asn: str | None = None
    as_name: str | None = None
    isp: str | None = None
    org: str | None = None
    is_proxy: bool | None = None
    is_hosting: bool | None = None
    is_mobile: bool | None = None
    flags: list[str] = Field(default_factory=list)
    error: str | None = None
    raw: dict[str, Any] | None = Field(default=None, exclude=True)


class NetworkInfo(BaseModel):
    asn: str | None = None
    as_name: str | None = None
    isp: str | None = None
    org: str | None = None
    rdns: str | None = None


class Classification(BaseModel):
    ip_type: Literal["native", "broadcast", "unknown"] = "unknown"
    usage: Literal["residential", "hosting", "mobile", "unknown"] = "unknown"
    proxy_signals: list[str] = Field(default_factory=list)
    address_class: str = "public"


class WhoisInfo(BaseModel):
    registry: str | None = None
    country: str | None = None
    netname: str | None = None
    org: str | None = None
    cidr: str | None = None
    allocated: str | None = None
    source: str | None = None
    raw_summary: str | None = None


class MapInfo(BaseModel):
    lat: float
    lon: float


class BlocklistHit(BaseModel):
    """A single positive match against one blocklist source."""
    source_id: str
    category: str
    severity: int
    detail: str | None = None
    matched_value: str
    homepage: str | None = None
    lookup_url: str | None = None


class BlocklistReport(BaseModel):
    hits: list[BlocklistHit] = Field(default_factory=list)
    checked_at: float
    source_counts: dict[str, int] = Field(default_factory=dict)
    refreshed_at: dict[str, float] = Field(default_factory=dict)
    source_homepages: dict[str, str] = Field(default_factory=dict)
    checked_ips: list[str] = Field(default_factory=list)
    checked_domain: str | None = None


class DnsRecords(BaseModel):
    domain: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)


class LookupReport(BaseModel):
    query: str
    query_type: Literal["ip", "domain"] = "ip"
    domain: str | None = None
    dns: DnsRecords | None = None
    client_ip: str | None = None
    ip_version: int
    sources: list[ProviderResult] = Field(default_factory=list)
    primary: ProviderResult | None = None
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    classification: Classification = Field(default_factory=Classification)
    risk_score: int = 0
    whois: WhoisInfo | None = None
    map: MapInfo | None = None
    # For domain queries: full reports for the other address family (A/AAAA)
    related: list["LookupReport"] = Field(default_factory=list)
    request_id: str
    cached: bool = False
    took_ms: int = 0
    blocklists: BlocklistReport | None = None
