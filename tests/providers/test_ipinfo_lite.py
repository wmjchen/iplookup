import httpx
import pytest
import respx

from app.providers.ipinfo_lite import IpinfoLiteProvider

LITE_RESPONSE = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}


def _provider() -> IpinfoLiteProvider:
    return IpinfoLiteProvider(token="test-token", timeout=2.0)


@pytest.mark.asyncio
async def test_ipinfo_lite_maps_response():
    with respx.mock:
        route = respx.get("https://api.ipinfo.io/lite/8.8.8.8").mock(
            return_value=httpx.Response(200, json=LITE_RESPONSE)
        )
        p = _provider()
        try:
            r = await p.lookup("8.8.8.8")
        finally:
            await p.aclose()
        assert r.error is None
        assert r.provider_id == "ipinfo_lite"
        assert r.country == "United States"
        assert r.country_code == "US"
        assert r.asn == "AS15169"
        assert r.as_name == "Google LLC"
        assert r.isp == "Google LLC"
        assert r.org == "google.com"
        assert route.calls.last.request.url.params["token"] == "test-token"


@pytest.mark.asyncio
async def test_ipinfo_lite_auth_error():
    with respx.mock:
        respx.get("https://api.ipinfo.io/lite/8.8.8.8").mock(
            return_value=httpx.Response(401, json={"error": "Invalid token"})
        )
        p = _provider()
        try:
            r = await p.lookup("8.8.8.8")
        finally:
            await p.aclose()
        assert r.error == "ipinfo lite auth failed (check IPINFO_TOKEN)"


@pytest.mark.asyncio
async def test_ipinfo_lite_http_error():
    with respx.mock:
        respx.get("https://api.ipinfo.io/lite/8.8.8.8").mock(
            return_value=httpx.Response(500)
        )
        p = _provider()
        try:
            r = await p.lookup("8.8.8.8")
        finally:
            await p.aclose()
        assert r.error == "HTTP 500"
