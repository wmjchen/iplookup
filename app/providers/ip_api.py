from __future__ import annotations

import httpx

from app.core.models import ProviderResult

FIELDS = (
    "status,message,country,countryCode,region,regionName,city,zip,lat,lon,"
    "timezone,isp,org,as,asname,mobile,proxy,hosting,query"
)


class IpApiProvider:
    provider_id = "ip_api"

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float = 1.2,
        base_url: str = "http://ip-api.com",
    ) -> None:
        self._client = client
        self._timeout = timeout
        self._base_url = base_url.rstrip("/")
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def lookup(
        self,
        ip: str,
        *,
        client_ip: str | None = None,
    ) -> ProviderResult:
        """Lookup via ip-api. Optionally forward client_ip for rate-limit attribution."""
        try:
            client = await self._get_client()
            headers: dict[str, str] = {}
            if client_ip:
                headers["X-Forwarded-For"] = client_ip
                headers["X-Real-IP"] = client_ip
            resp = await client.get(
                f"{self._base_url}/json/{ip}",
                params={"fields": FIELDS},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "success":
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error=data.get("message") or "ip-api lookup failed",
                )
            as_field = data.get("as") or ""
            asn = as_field.split(" ")[0] if as_field else None
            as_name = data.get("asname") or (
                " ".join(as_field.split(" ")[1:]) if as_field else None
            )
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName") or data.get("region"),
                city=data.get("city"),
                postal=data.get("zip"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                timezone=data.get("timezone"),
                asn=asn,
                as_name=as_name,
                isp=data.get("isp"),
                org=data.get("org"),
                is_proxy=data.get("proxy"),
                is_hosting=data.get("hosting"),
                is_mobile=data.get("mobile"),
                raw=data,
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
