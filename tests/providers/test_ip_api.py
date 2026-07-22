import httpx
import pytest
import respx

from app.providers.ip_api import IpApiProvider


@pytest.mark.asyncio
@respx.mock
async def test_ip_api_success():
    route = respx.get("http://ip-api.com/json/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "region": "VA",
                "regionName": "Virginia",
                "city": "Ashburn",
                "zip": "20149",
                "lat": 39.03,
                "lon": -77.5,
                "timezone": "America/New_York",
                "isp": "Google LLC",
                "org": "Google Public DNS",
                "as": "AS15169 Google LLC",
                "asname": "GOOGLE",
                "mobile": False,
                "proxy": False,
                "hosting": True,
                "query": "8.8.8.8",
            },
        )
    )
    provider = IpApiProvider()
    try:
        result = await provider.lookup("8.8.8.8", client_ip="203.0.113.50")
        assert result.error is None
        assert result.country_code == "US"
        assert result.city == "Ashburn"
        assert result.asn == "AS15169"
        assert result.is_hosting is True
        assert route.calls.last.request.headers["x-forwarded-for"] == "203.0.113.50"
        assert route.calls.last.request.headers["x-real-ip"] == "203.0.113.50"
    finally:
        await provider.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_ip_api_failure_status():
    respx.get("http://ip-api.com/json/1.2.3.4").mock(
        return_value=httpx.Response(
            200, json={"status": "fail", "message": "invalid query"}
        )
    )
    provider = IpApiProvider()
    try:
        result = await provider.lookup("1.2.3.4")
        assert result.error == "invalid query"
    finally:
        await provider.aclose()
