from app.core.models import ProviderResult


def test_provider_result_flags_default_empty():
    r = ProviderResult(provider_id="x", ip="1.2.3.4")
    assert r.flags == []


def test_provider_result_flags_serialize_roundtrip():
    r = ProviderResult(provider_id="ipfire", ip="1.1.1.1", flags=["anycast"])
    data = r.model_dump()
    assert data["flags"] == ["anycast"]
    r2 = ProviderResult(**data)
    assert r2.flags == ["anycast"]
    assert '"anycast"' in r.model_dump_json()
