from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.models import ProviderResult

# The BIN reader returns this exact string for fields a DB edition lacks.
UNAVAILABLE = "This parameter is unavailable in selected .BIN data file. Please upgrade data file."


def _clean(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if not value or value.startswith(UNAVAILABLE):
            return None
    return value


def _as_float(value: Any) -> float | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class Ip2LocationProvider:
    """
    IP2Location LITE BIN (https://lite.ip2location.com). Attribution required
    (see web/index.html footer + README). Edition auto-detected by the library.
    """

    provider_id = "ip2location"

    def __init__(self, db_path: Path, reader: Any | None = None) -> None:
        self._path = db_path
        if reader is not None:
            self._reader = reader
        elif db_path.exists():
            import IP2Location

            self._reader = IP2Location.IP2Location(str(db_path))
        else:
            self._reader = None

    def close(self) -> None:
        self._reader = None

    @property
    def available(self) -> bool:
        return self._reader is not None

    async def lookup(self, ip: str) -> ProviderResult:
        if self._reader is None:
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error="ip2location database not loaded",
            )
        try:
            rec = self._reader.get_all(ip)
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=_clean(getattr(rec, "country_long", None)),
                country_code=_clean(getattr(rec, "country_short", None)),
                region=_clean(getattr(rec, "region", None)),
                city=_clean(getattr(rec, "city", None)),
                postal=_clean(getattr(rec, "zipcode", None)),
                latitude=_as_float(getattr(rec, "latitude", None)),
                longitude=_as_float(getattr(rec, "longitude", None)),
                timezone=_clean(getattr(rec, "timezone", None)),
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
