import httpx
import pytest
import respx

from app.blocklists.sources.stevenblack import StevenblackHostsSource


def test_stevenblack_unified():
    s = StevenblackHostsSource(category=None)
    assert s.source_id == "stevenblack_hosts"
    assert s.url == (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts"
    )
    assert s.category == "adware"


@pytest.mark.asyncio
@respx.mock
async def test_stevenblack_fetch_and_parse():
    body = """# Title: StevenBlack hosts
0.0.0.0 adware.example.com
0.0.0.0 tracker.example.com
127.0.0.1 localhost
"""
    respx.get(
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts"
    ).mock(return_value=httpx.Response(200, content=body.encode()))
    src = StevenblackHostsSource(category=None)
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        assert "adware.example.com" in data.domains
        assert "tracker.example.com" in data.domains
        assert src.matches_domain("subdomain.adware.example.com", data) == "adware.example.com"
        assert src.matches_domain("evil.com", data) is None
    finally:
        await client.aclose()


def test_stevenblack_category_paths():
    assert StevenblackHostsSource(category="fakenews").source_id == "stevenblack_fakenews"
    assert StevenblackHostsSource(category="fakenews").url == (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts"
    )
    assert StevenblackHostsSource(category="gambling").source_id == "stevenblack_gambling"
    assert StevenblackHostsSource(category="porn").source_id == "stevenblack_porn"
    assert StevenblackHostsSource(category="social").source_id == "stevenblack_social"
    assert StevenblackHostsSource(category="adware").source_id == "stevenblack_adware"


def test_stevenblack_invalid_category():
    with pytest.raises(ValueError):
        StevenblackHostsSource(category="not-a-cat")
