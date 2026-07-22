from app.core.models import BlocklistHit, ProviderResult
from app.core.risk import score_risk


def _src(**kwargs) -> ProviderResult:
    base = dict(
        provider_id="t",
        ip="1.1.1.1",
        country="Australia",
        country_code="AU",
        region="Queensland",
        city="Brisbane",
    )
    base.update(kwargs)
    return ProviderResult(**base)


def test_clean_residential_low_score():
    sources = [
        _src(
            provider_id="maxmind",
            is_hosting=False,
            is_proxy=False,
            isp="Comcast Cable",
            org="Comcast",
            as_name="COMCAST",
        ),
        _src(
            provider_id="ip_api",
            is_hosting=False,
            is_proxy=False,
            isp="Comcast Cable",
            org="Comcast",
        ),
    ]
    score = score_risk(
        sources=sources,
        is_hosting=False,
        is_proxy=False,
        is_mobile=False,
        is_private=False,
        proxy_signals=[],
    )
    assert score == 0


def test_hosting_raises_score():
    sources = [_src(is_hosting=True)]
    score = score_risk(
        sources=sources,
        is_hosting=True,
        is_proxy=False,
        is_mobile=False,
        is_private=False,
        proxy_signals=["hosting_asn"],
    )
    assert score >= 40


def test_proxy_and_hosting_high():
    score = score_risk(
        sources=[_src(is_proxy=True, is_hosting=True)],
        is_hosting=True,
        is_proxy=True,
        is_mobile=False,
        is_private=False,
        proxy_signals=["hosting_asn", "provider_proxy_flag"],
    )
    assert score >= 70
    assert score <= 100


def test_country_disagreement():
    sources = [
        _src(provider_id="a", country_code="US", city="Ashburn"),
        _src(provider_id="b", country_code="DE", city="Frankfurt"),
    ]
    score = score_risk(
        sources=sources,
        is_hosting=False,
        is_proxy=False,
        is_mobile=False,
        is_private=False,
        proxy_signals=[],
    )
    assert score >= 15


def test_private_ip_score_zero():
    score = score_risk(
        sources=[],
        is_hosting=False,
        is_proxy=False,
        is_mobile=False,
        is_private=True,
        proxy_signals=[],
    )
    assert score == 0


def test_blocklist_hits_add_to_score():
    hits = [BlocklistHit(
        source_id="spamhaus_drop", category="hijacked_network", severity=25,
        matched_value="1.2.3.4",
    )]
    score = score_risk(
        sources=[_src()],
        is_hosting=False, is_proxy=False, is_mobile=False, is_private=False,
        proxy_signals=[], blocklist_hits=hits,
    )
    assert score >= 25


def test_blocklist_hits_capped_at_50():
    hits = [
        BlocklistHit(source_id="a", category="x", severity=25, matched_value="1.1.1.1"),
        BlocklistHit(source_id="b", category="y", severity=25, matched_value="1.1.1.1"),
        BlocklistHit(source_id="c", category="z", severity=25, matched_value="1.1.1.1"),
    ]
    score = score_risk(
        sources=[_src()],
        is_hosting=False, is_proxy=False, is_mobile=False, is_private=False,
        proxy_signals=[], blocklist_hits=hits,
    )
    assert score == 50  # cap


def test_blocklist_hits_none_no_change():
    score = score_risk(
        sources=[_src()],
        is_hosting=False, is_proxy=False, is_mobile=False, is_private=False,
        proxy_signals=[], blocklist_hits=None,
    )
    assert score == 0


def test_blocklist_hits_total_capped_at_100():
    hits = [
        BlocklistHit(source_id="a", category="x", severity=50, matched_value="1.1.1.1"),
    ]
    score = score_risk(
        sources=[_src(is_proxy=True, is_hosting=True)],
        is_hosting=True, is_proxy=True, is_mobile=False, is_private=False,
        proxy_signals=["hosting_asn", "provider_proxy_flag"],
        blocklist_hits=hits,
    )
    assert score == 100  # never exceeds 100


def test_score_risk_hostile_network_adds_points():
    base = score_risk(
        sources=[], is_hosting=False, is_proxy=False, is_mobile=False,
        is_private=False, proxy_signals=[],
    )
    hostile = score_risk(
        sources=[], is_hosting=False, is_proxy=False, is_mobile=False,
        is_private=False, proxy_signals=["ipfire_hostile_network"],
    )
    assert base == 0
    assert hostile == 20
