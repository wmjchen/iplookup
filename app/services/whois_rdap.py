from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from app.core.models import WhoisInfo

BOOTSTRAP = "https://rdap.org/ip/{ip}"


def _country_from_vcard(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if not item:
            continue
        if item[0] == "adr":
            # adr value is often a list; country is last component
            val = item[-1]
            if isinstance(val, list) and val:
                country = val[-1]
                if isinstance(country, str) and country.strip():
                    return country.strip()
        if item[0] == "country-name" and isinstance(item[-1], str):
            return item[-1].strip()
    return None


def _extract_from_rdap(data: dict[str, Any]) -> WhoisInfo:
    country = data.get("country")
    name = data.get("name")
    handle = data.get("handle")
    cidr = None
    cidrs = data.get("cidr0_cidrs") or data.get("ipAddress")
    if isinstance(cidrs, list) and cidrs:
        first = cidrs[0]
        if isinstance(first, dict):
            v4 = first.get("v4prefix")
            v6 = first.get("v6prefix")
            length = first.get("length")
            prefix = v4 or v6
            if prefix and length is not None:
                cidr = f"{prefix}/{length}"
    elif isinstance(cidrs, dict):
        start = cidrs.get("startAddress") or cidrs.get("ipAddress")
        end = cidrs.get("endAddress")
        if start and end:
            cidr = f"{start} - {end}"

    org = None
    entities = data.get("entities") or []
    for ent in entities:
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray")
        if country is None:
            country = _country_from_vcard(vcard)
        if "registrant" in roles or "administrative" in roles or not org:
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        org = item[-1]
                        break
            if org and country:
                break

    # Normalize country names/codes lightly: keep ISO if already 2 letters
    if isinstance(country, str) and len(country.strip()) > 2:
        # leave full name; native/broadcast compares codes — map common
        country = country.strip()

    port43 = data.get("port43")
    registry = None
    if port43:
        # e.g. whois.arin.net -> ARIN
        host = str(port43).lower()
        for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
            if rir in host:
                registry = rir.upper()
                break
        if registry is None:
            parts = host.split(".")
            registry = parts[-2].upper() if len(parts) >= 2 else parts[0].upper()
    elif isinstance(data.get("rdapConformance"), list):
        registry = "RDAP"

    events = data.get("events") or []
    allocated = None
    for ev in events:
        if ev.get("eventAction") in {"registration", "allocated", "last changed"}:
            allocated = ev.get("eventDate")
            if ev.get("eventAction") in {"registration", "allocated"}:
                break

    return WhoisInfo(
        registry=registry,
        country=country,
        netname=name or handle,
        org=org,
        cidr=cidr,
        allocated=allocated,
        source="rdap",
        raw_summary=None,
    )


class RdapClient:
    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float = 1.5,
        bootstrap_url: str = BOOTSTRAP,
    ) -> None:
        self._client = client
        self._timeout = timeout
        self._bootstrap_url = bootstrap_url
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=True)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup(self, ip: str) -> WhoisInfo | None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        try:
            client = await self._get_client()
            url = self._bootstrap_url.format(ip=ip)
            resp = await client.get(url)
            if resp.status_code >= 400:
                return WhoisInfo(source="rdap", raw_summary=f"HTTP {resp.status_code}")
            data = resp.json()
            return _extract_from_rdap(data)
        except Exception as exc:  # noqa: BLE001
            return WhoisInfo(source="rdap", raw_summary=str(exc))
