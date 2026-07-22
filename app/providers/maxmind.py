from __future__ import annotations

from pathlib import Path
from typing import Any

import maxminddb

from app.core.models import ProviderResult


class MaxMindProvider:
    provider_id = "maxmind"

    def __init__(
        self,
        city_db: Path,
        asn_db: Path | None = None,
        hosting_check: Any | None = None,
    ) -> None:
        self._city_path = city_db
        self._asn_path = asn_db
        self._city = maxminddb.open_database(str(city_db)) if city_db.exists() else None
        self._asn = (
            maxminddb.open_database(str(asn_db))
            if asn_db is not None and asn_db.exists()
            else None
        )
        self._hosting_check = hosting_check

    def close(self) -> None:
        if self._city is not None:
            self._city.close()
        if self._asn is not None:
            self._asn.close()

    @property
    def available(self) -> bool:
        return self._city is not None

    async def lookup(self, ip: str) -> ProviderResult:
        if self._city is None:
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error="maxmind city database not loaded",
            )
        try:
            city = self._city.get(ip) or {}
            asn_rec = self._asn.get(ip) if self._asn is not None else None
            asn_rec = asn_rec or {}

            country = (city.get("country") or {}) if isinstance(city, dict) else {}
            reg = (city.get("registered_country") or {}) if isinstance(city, dict) else {}
            subdivs = city.get("subdivisions") or []
            region = None
            if subdivs:
                region = subdivs[0].get("names", {}).get("en") or subdivs[0].get(
                    "iso_code"
                )
            city_names = (city.get("city") or {}).get("names") or {}
            loc = city.get("location") or {}
            postal = (city.get("postal") or {}).get("code")

            asn_num = asn_rec.get("autonomous_system_number")
            as_name = asn_rec.get("autonomous_system_organization")
            asn = f"AS{asn_num}" if asn_num else None

            is_hosting = None
            if self._hosting_check is not None and asn_num is not None:
                is_hosting = bool(self._hosting_check.contains(asn_num))

            country_name = (country.get("names") or {}).get("en") or (
                reg.get("names") or {}
            ).get("en")
            country_code = country.get("iso_code") or reg.get("iso_code")

            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=country_name,
                country_code=country_code,
                region=region,
                city=city_names.get("en"),
                postal=postal,
                latitude=loc.get("latitude"),
                longitude=loc.get("longitude"),
                timezone=loc.get("time_zone"),
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
