from __future__ import annotations

from app.core.iputil import is_public_ip, parse_ip


def _first_valid_public(candidates: list[str]) -> str | None:
    for raw in candidates:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ip = parse_ip(raw)
        except ValueError:
            continue
        if is_public_ip(ip):
            return str(ip)
    return None


def resolve_client_ip(
    headers: dict[str, str],
    peer: str | None,
    trust_proxy: bool = True,
) -> str:
    normalized = {k.lower(): v for k, v in headers.items()}

    if trust_proxy:
        for key in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
            val = normalized.get(key)
            if val:
                found = _first_valid_public([val])
                if found:
                    return found

        xff = normalized.get("x-forwarded-for")
        if xff:
            found = _first_valid_public([p.strip() for p in xff.split(",")])
            if found:
                return found

    if peer:
        try:
            return str(parse_ip(peer))
        except ValueError:
            pass

    return peer or "0.0.0.0"
