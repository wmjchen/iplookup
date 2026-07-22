from __future__ import annotations

from app.core.models import BlocklistHit, ProviderResult

HOSTING_POINTS = 40
PROXY_POINTS = 30
COUNTRY_DISAGREE_POINTS = 15
CITY_DISAGREE_POINTS = 5
MOBILE_POINTS = 5
INFRA_SIGNAL_POINTS = 10
BLOCKLIST_CAP = 50
HOSTILE_NETWORK_POINTS = 20


def score_risk(
    *,
    sources: list[ProviderResult],
    is_hosting: bool,
    is_proxy: bool,
    is_mobile: bool,
    is_private: bool,
    proxy_signals: list[str],
    blocklist_hits: list[BlocklistHit] | None = None,
) -> int:
    if is_private:
        return 0

    score = 0
    hosting_signals = {
        "hosting_asn",
        "provider_hosting_flag",
        "infra_asn",
        "infra_keyword",
        "ip_index_hosting",
    }
    if is_hosting or hosting_signals.intersection(proxy_signals):
        score += HOSTING_POINTS
        extra = len(hosting_signals.intersection(proxy_signals))
        if extra > 1:
            score += INFRA_SIGNAL_POINTS
    if is_proxy or "provider_proxy_flag" in proxy_signals:
        score += PROXY_POINTS
    if "ipfire_hostile_network" in proxy_signals:
        score += HOSTILE_NETWORK_POINTS
    if is_mobile:
        score += MOBILE_POINTS

    codes = {
        (s.country_code or "").upper()
        for s in sources
        if s.error is None and s.country_code
    }
    if len(codes) > 1:
        score += COUNTRY_DISAGREE_POINTS

    cities = {
        (s.city or "").lower()
        for s in sources
        if s.error is None and s.city and s.country_code
    }
    if len(codes) <= 1 and len(cities) > 1:
        score += CITY_DISAGREE_POINTS

    if blocklist_hits:
        blocklist_pts = sum(h.severity for h in blocklist_hits)
        score += min(blocklist_pts, BLOCKLIST_CAP)

    return min(score, 100)
