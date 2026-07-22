from __future__ import annotations

from typing import Sequence

from app.core.models import ProviderResult

# Well-known infrastructure / anycast / public-DNS / CDN ASNs often missing from
# "top cloud hosting" lists (e.g. Quad9 AS19281).
INFRA_ASNS: frozenset[int] = frozenset(
    {
        19281,  # Quad9
        11232,  # Midcontinent / various anycast edges appear elsewhere
        36692,  # Cisco OpenDNS / Umbrella
        30148,  # Sucuri
        13335,  # Cloudflare
        209242,  # Cloudflare WARP / related
        54113,  # Fastly
        16625,  # Akamai
        20940,  # Akamai
        15169,  # Google
        396982,  # Google Cloud
        16509,  # Amazon
        14618,  # Amazon
        8075,  # Microsoft
        8068,  # Microsoft
        14061,  # DigitalOcean
        63949,  # Linode/Akamai
        24940,  # Hetzner
        16276,  # OVH
        20473,  # Choopa/Vultr
        31898,  # Oracle Cloud
        45102,  # Alibaba
        132203,  # Tencent
        37963,  # Alibaba
        60068,  # CDN77
        60011,  # Hurricane Electric often transit — skip
        6939,  # Hurricane Electric
        174,  # Cogent (transit) — skip treating as hosting alone
        3356,  # Level3/Lumen transit
    }
)

# Remove pure transit ASNs that shouldn't force hosting by ASN alone
INFRA_ASNS = frozenset(
    a
    for a in INFRA_ASNS
    if a
    not in {
        174,
        3356,
        6939,
        60011,
        11232,
    }
)

HOSTING_KEYWORDS: tuple[str, ...] = (
    "amazon",
    "aws",
    "ec2",
    "google cloud",
    "google llc",
    "google public dns",
    "digitalocean",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "cloudflare",
    "fastly",
    "microsoft",
    "azure",
    "alibaba",
    "tencent",
    "contabo",
    "leaseweb",
    "colo",
    "colocation",
    "hosting",
    "datacenter",
    "data center",
    "data-center",
    "server",
    "vps",
    "dedicated",
    "quad9",
    "opendns",
    "umbrella",
    "anycast",
    "cdn",
    "softlayer",
    "ibm cloud",
    "oracle cloud",
    "hurricane electric",  # often infra, not residential
    "cogent",  # transit/datacenter-ish; weak
)

# Strong residential ISP name fragments (positive signal)
RESIDENTIAL_KEYWORDS: tuple[str, ...] = (
    "comcast",
    "xfinity",
    "verizon",
    "at&t",
    "att ",
    "charter",
    "spectrum",
    "cox communication",
    "shaw communication",
    "rogers cable",
    "bell canada",
    "telus",
    "bt public",
    "deutsche telekom",
    "orange s.a",
    "vodafone",
    "t-mobile",
    "sprint",
    "frontier communication",
    "centurylink",
    "lumen residential",
    "virgin media",
    "sky broadband",
    "telecom italia",
    "telefonica",
    "china telecom",
    "china unicom",
    "china mobile",
    "residential",
    "broadband",
    "cable",
    "dsl",
    "ftth",
    "fiber home",
)


def _parse_asn(asn: str | int | None) -> int | None:
    if asn is None:
        return None
    if isinstance(asn, int):
        return asn
    token = str(asn).strip().upper()
    if token.startswith("AS"):
        token = token[2:]
    try:
        return int(token)
    except ValueError:
        return None


def hosting_keyword_hit(text: str | None) -> bool:
    if not text:
        return False
    blob = text.lower()
    return any(k in blob for k in HOSTING_KEYWORDS)


def residential_keyword_hit(text: str | None) -> bool:
    if not text:
        return False
    blob = text.lower()
    return any(k in blob for k in RESIDENTIAL_KEYWORDS)


def source_blob(s: ProviderResult) -> str:
    return " ".join(filter(None, [s.org, s.isp, s.as_name, s.asn]))


def merge_usage_signals(
    sources: Sequence[ProviderResult],
) -> tuple[bool, bool, bool | None, list[str]]:
    is_hosting = False
    is_proxy = False
    is_mobile: bool | None = None
    signals: list[str] = []

    for s in sources:
        if s.error:
            continue
        if s.is_hosting is True:
            is_hosting = True
            if "provider_hosting_flag" not in signals:
                signals.append("provider_hosting_flag")
        if s.is_proxy is True:
            is_proxy = True
            if "provider_proxy_flag" not in signals:
                signals.append("provider_proxy_flag")
        if s.is_mobile is True:
            is_mobile = True
        elif s.is_mobile is False and is_mobile is None:
            is_mobile = False

        asn_num = _parse_asn(s.asn)
        if asn_num is not None and asn_num in INFRA_ASNS:
            is_hosting = True
            if "infra_asn" not in signals:
                signals.append("infra_asn")

        if hosting_keyword_hit(source_blob(s)):
            is_hosting = True
            if "infra_keyword" not in signals:
                signals.append("infra_keyword")

        # MaxMind hosting list flag
        if s.provider_id == "maxmind" and s.is_hosting is True:
            if "hosting_asn" not in signals:
                signals.append("hosting_asn")
            is_hosting = True

        # Umkus/ip-index hosting flag (IP-range enriched ASN DB)
        if s.provider_id == "ip_index" and s.is_hosting is True:
            if "ip_index_hosting" not in signals:
                signals.append("ip_index_hosting")
            is_hosting = True

        # IPFire hostile network flag
        if "hostile_network" in s.flags and "ipfire_hostile_network" not in signals:
            signals.append("ipfire_hostile_network")

    return is_hosting, is_proxy, is_mobile, signals


def classify_usage(
    *,
    is_hosting: bool,
    is_mobile: bool | None,
    is_private: bool,
    signals: list[str] | None = None,
    sources: Sequence[ProviderResult] | None = None,
) -> str:
    if is_private:
        return "unknown"
    if is_hosting:
        return "hosting"
    if is_mobile:
        return "mobile"

    # Positive residential evidence only → residential; else unknown
    if sources:
        for s in sources:
            if s.error:
                continue
            if residential_keyword_hit(source_blob(s)):
                return "residential"
    return "unknown"
