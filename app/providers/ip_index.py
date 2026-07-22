from __future__ import annotations

from pathlib import Path

import maxminddb

from app.core.models import ProviderResult


def _as_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "true", "yes", "y"}:
            return True
        if v in {"0", "false", "no", "n"}:
            return False
    return None


class IpIndexProvider:
    """
    Umkus/ip-index MMDB: ASN + country + hosting flag.
    Daily free community DB: https://github.com/Umkus/ip-index
    """

    provider_id = "ip_index"

    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._db = maxminddb.open_database(str(db_path)) if db_path.exists() else None

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    @property
    def available(self) -> bool:
        return self._db is not None

    async def lookup(self, ip: str) -> ProviderResult:
        if self._db is None:
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error="ip-index database not loaded",
            )
        try:
            rec = self._db.get(ip)
            if not rec:
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error="no data",
                )
            asn_num = rec.get("asn")
            asn = f"AS{asn_num}" if asn_num is not None else None
            as_name = rec.get("asn_name") or rec.get("as_name") or rec.get("name")
            country_code = rec.get("country") or rec.get("country_code")
            if isinstance(country_code, str):
                country_code = country_code.upper()
            is_hosting = _as_bool(rec.get("hosting"))
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=country_code,
                country_code=country_code,
                asn=asn,
                as_name=as_name,
                isp=as_name,
                org=as_name,
                is_hosting=is_hosting,
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
