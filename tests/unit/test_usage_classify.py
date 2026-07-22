from app.core.models import ProviderResult
from app.core.usage import classify_usage, hosting_keyword_hit, merge_usage_signals


def _src(**kwargs) -> ProviderResult:
    base = dict(provider_id="t", ip="9.9.9.9")
    base.update(kwargs)
    return ProviderResult(**base)


def test_quad9_keyword_or_asn_is_hosting():
    sources = [
        _src(
            provider_id="maxmind",
            asn="AS19281",
            as_name="Quad9",
            isp="Quad9",
            org="Quad9",
            is_hosting=False,
        )
    ]
    is_hosting, is_proxy, is_mobile, signals = merge_usage_signals(sources)
    assert is_hosting is True
    assert "infra_keyword" in signals or "infra_asn" in signals
    assert classify_usage(is_hosting=is_hosting, is_mobile=is_mobile, is_private=False) == "hosting"


def test_explicit_hosting_flag():
    sources = [_src(is_hosting=True, asn="AS15169", as_name="GOOGLE")]
    is_hosting, _, _, signals = merge_usage_signals(sources)
    assert is_hosting is True
    assert "provider_hosting_flag" in signals


def test_ip_index_hosting_signal():
    sources = [
        _src(
            provider_id="ip_index",
            asn="AS15169",
            as_name="GOOGLE",
            is_hosting=True,
        )
    ]
    is_hosting, _, _, signals = merge_usage_signals(sources)
    assert is_hosting is True
    assert "ip_index_hosting" in signals


def test_unknown_when_no_signals():
    sources = [
        _src(
            asn="AS64500",
            as_name="Example Research Lab",
            isp="Example Research Lab",
            org="Example Research Lab",
        )
    ]
    is_hosting, is_proxy, is_mobile, signals = merge_usage_signals(sources)
    assert is_hosting is False
    usage = classify_usage(
        is_hosting=is_hosting,
        is_mobile=is_mobile,
        is_private=False,
        signals=signals,
        sources=sources,
    )
    # No positive residential proof either → unknown, not residential
    assert usage == "unknown"


def test_residential_isp_keyword():
    sources = [
        _src(
            asn="AS7922",
            as_name="Comcast Cable",
            isp="Comcast Cable Communications",
            org="Comcast Cable",
        )
    ]
    is_hosting, _, is_mobile, signals = merge_usage_signals(sources)
    usage = classify_usage(
        is_hosting=is_hosting,
        is_mobile=is_mobile,
        is_private=False,
        signals=signals,
        sources=sources,
    )
    assert usage == "residential"


def test_hosting_keyword_hit():
    assert hosting_keyword_hit("Quad9 DNS") is True
    assert hosting_keyword_hit("Amazon.com") is True
    assert hosting_keyword_hit("Shaw Communications") is False


def test_merge_usage_signals_ipfire_hostile():
    s = ProviderResult(provider_id="ipfire", ip="6.6.6.6", flags=["hostile_network"])
    is_hosting, is_proxy, is_mobile, signals = merge_usage_signals([s])
    assert "ipfire_hostile_network" in signals
    assert is_hosting is False
    assert is_proxy is False


def test_merge_usage_signals_ipfire_anonymous_proxy_via_is_proxy():
    s = ProviderResult(
        provider_id="ipfire", ip="6.6.6.6", is_proxy=True, flags=["anonymous_proxy"]
    )
    _, is_proxy, _, signals = merge_usage_signals([s])
    assert is_proxy is True
    assert "provider_proxy_flag" in signals
