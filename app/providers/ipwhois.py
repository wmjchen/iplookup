from __future__ import annotations

import httpx

from app.core.models import ProviderResult


class IpWhoisProvider:
    """Free remote provider: ipwho.is"""

    provider_id = "ipwhois"

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float = 1.2,
        base_url: str = "https://ipwho.is",
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

    async def lookup(self, ip: str) -> ProviderResult:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self._base_url}/{ip}")
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success", True):
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error=data.get("message") or "ipwho.is lookup failed",
                )
            conn = data.get("connection") or {}
            asn_num = conn.get("asn")
            asn = f"AS{asn_num}" if asn_num else None
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=data.get("country"),
                country_code=data.get("country_code"),
                region=data.get("region"),
                city=data.get("city"),
                postal=data.get("postal"),
                latitude=data.get("latitude"),
                longitude=data.get("longitude"),
                timezone=(data.get("timezone") or {}).get("id")
                if isinstance(data.get("timezone"), dict)
                else data.get("timezone"),
                asn=asn,
                as_name=conn.get("org") or conn.get("isp"),
                isp=conn.get("isp"),
                org=conn.get("org"),
                raw=data,
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
