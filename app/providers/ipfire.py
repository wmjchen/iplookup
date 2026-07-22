from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.models import ProviderResult
from app.vendor.pylibloc import LocDB

# Flag bits from libloc src/libloc/network.h; verified against the live DB
# (1.1.1.1/8.8.8.8/9.9.9.9 -> ANYCAST; Tor exit 171.25.193.20 -> ANONYMOUS_PROXY).
FLAG_ANONYMOUS_PROXY = 1 << 0
FLAG_SATELLITE_PROVIDER = 1 << 1
FLAG_ANYCAST = 1 << 2
FLAG_HOSTILE_NETWORK = 1 << 3  # libloc: LOC_NETWORK_FLAG_DROP

_FLAG_NAMES = (
    (FLAG_ANONYMOUS_PROXY, "anonymous_proxy"),
    (FLAG_SATELLITE_PROVIDER, "satellite"),
    (FLAG_ANYCAST, "anycast"),
    (FLAG_HOSTILE_NETWORK, "hostile_network"),
)


def flag_names(flags: int) -> list[str]:
    return [name for bit, name in _FLAG_NAMES if flags & bit]


class IpfireProvider:
    """
    IPFire Location DB (https://www.ipfire.org/location/), CC BY-SA 4.0.
    Country + ASN + network flags via vendored pylibloc. Country-level only.
    """

    provider_id = "ipfire"

    def __init__(self, db_path: Path, db: Any | None = None) -> None:
        self._path = db_path
        if db is not None:
            self._db = db
        elif db_path.exists():
            self._db = LocDB(str(db_path), debug=0)
        else:
            self._db = None

    def close(self) -> None:
        self._db = None  # pylibloc loads fully into memory; nothing to close

    @property
    def available(self) -> bool:
        return self._db is not None

    async def lookup(self, ip: str) -> ProviderResult:
        if self._db is None:
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error="ipfire database not loaded",
            )
        try:
            res = self._db.lookup(ip)
            if not res:
                return ProviderResult(
                    provider_id=self.provider_id,
                    ip=ip,
                    error="no data",
                )
            cos, asn_num, as_name, flags, _mask = res
            as_name = as_name if as_name != "N/A" else None
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                country=cos[2] if cos else None,
                country_code=cos[0] if cos else None,
                asn=f"AS{asn_num}" if asn_num else None,
                as_name=as_name,
                isp=as_name,
                org=as_name,
                is_proxy=True if flags & FLAG_ANONYMOUS_PROXY else None,
                flags=flag_names(flags),
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=self.provider_id,
                ip=ip,
                error=str(exc),
            )
