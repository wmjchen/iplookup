from __future__ import annotations

import re

from app.core.iputil import parse_ip, validate_query_ip

# Practical hostname check (not full IDNA); labels + TLD
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_hostname(value: str) -> bool:
    value = value.strip().rstrip(".").lower()
    if not value or " " in value or "/" in value:
        return False
    try:
        parse_ip(value)
        return False
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def normalize_hostname(value: str) -> str:
    return value.strip().rstrip(".").lower()


def classify_query(value: str) -> tuple[str, str]:
    """
    Return (kind, normalized) where kind is 'ip' or 'domain'.
    Raises ValueError if neither.
    """
    raw = value.strip()
    if not raw:
        raise ValueError("empty query")
    try:
        return "ip", validate_query_ip(raw)
    except ValueError:
        pass
    if is_hostname(raw):
        return "domain", normalize_hostname(raw)
    raise ValueError(f"invalid ip or domain: {value}")
