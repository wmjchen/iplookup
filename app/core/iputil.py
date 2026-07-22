from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv6Address

IPAddress = IPv4Address | IPv6Address


def parse_ip(value: str) -> IPAddress:
    return ipaddress.ip_address(value.strip())


def ip_version(ip: IPAddress) -> int:
    return ip.version


def is_public_ip(ip: IPAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def classify_address(ip: IPAddress) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    return "public"


def validate_query_ip(value: str) -> str:
    ip = parse_ip(value)
    return str(ip)
