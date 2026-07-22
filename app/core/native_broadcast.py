from __future__ import annotations

from typing import Literal

IpType = Literal["native", "broadcast", "unknown"]


def classify_native_broadcast(
    *,
    usage_country_code: str | None,
    registration_country_code: str | None,
) -> IpType:
    if not usage_country_code or not registration_country_code:
        return "unknown"
    usage = usage_country_code.strip().upper()
    reg = registration_country_code.strip().upper()
    if not usage or not reg:
        return "unknown"
    if usage == reg:
        return "native"
    return "broadcast"
