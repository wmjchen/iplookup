from __future__ import annotations

import httpx

from app.core.models import ProviderResult


class IpinfoLiteProvider:
    """
    IPinfo Lite API (https://ipinfo.io/lite): free token, unlimited requests.
    Country + ASN only (no city/coords). Proxied server-side to hide the token.
    """

    provider_id = "ipinfo_lite"

    def __init__(
        self,
        token: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 1.2,
        base_url: str = "https://api.ipinfo.io",
    ) -> None:
        self._token = token
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
            resp = await client.get(
                f"{self._base_url}/lite/{ip}",
                params={"token": self._token},
            )
            if resp.status_code in {401, 403}:
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error="ipinfo lite auth failed (check IPINFO_TOKEN)",
                )
            if resp.status_code != 200:
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error=f"HTTP {resp.status_code}",
                )
            data = resp.json()
            return ProviderResult(
                provider_id=self.provider_id,
                ip=data.get("ip") or ip,
                country=data.get("country"),
                country_code=data.get("country_code"),
                asn=data.get("asn"),
                as_name=data.get("as_name"),
                isp=data.get("as_name"),
                org=data.get("as_domain"),
                raw=data,
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
