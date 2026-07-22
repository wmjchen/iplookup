import httpx
import respx
from fastapi.testclient import TestClient

from app.core.models import ProviderResult, WhoisInfo
from app.core.orchestrator import LookupOrchestrator
from app.main import app
from app.providers.ip_api import IpApiProvider
from app.providers.ipinfo_lite import IpinfoLiteProvider
from app.services.whois_rdap import RdapClient


class FakeRdap(RdapClient):
    async def lookup(self, ip: str) -> WhoisInfo | None:
        return WhoisInfo(country="US", source="rdap")


class FakeProvider:
    provider_id = "maxmind"

    async def lookup(self, ip: str) -> ProviderResult:
        return ProviderResult(provider_id="maxmind", ip=ip, country_code="US")


def test_ip_api_proxy_forwards_client_ip():
    with TestClient(app) as c:
        ip_api = IpApiProvider(timeout=2.0)
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()],
            rdap=FakeRdap(),
            cache=None,
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.ip_api = ip_api
        c.app.state.maxmind_loaded = True
        c.app.state.hosting_asn_count = 0
        c.app.state.resolve_ip = lambda request: "9.9.9.9"

        with respx.mock:
            route = respx.get("http://ip-api.com/json/8.8.8.8").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "country": "United States",
                        "countryCode": "US",
                        "regionName": "Virginia",
                        "city": "Ashburn",
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
            r = c.get("/api/providers/ip-api", params={"ip": "8.8.8.8"})
            assert r.status_code == 200
            data = r.json()
            assert data["provider_id"] == "ip_api"
            assert data["country_code"] == "US"
            assert data["error"] is None
            assert route.calls.last.request.headers["x-forwarded-for"] == "9.9.9.9"


def test_ip_api_proxy_invalid_ip():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()],
            rdap=FakeRdap(),
            cache=None,
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.ip_api = IpApiProvider(timeout=2.0)
        c.app.state.resolve_ip = lambda request: "9.9.9.9"
        r = c.get("/api/providers/ip-api", params={"ip": "nope"})
        assert r.status_code == 400


def test_ipinfo_lite_proxy_success():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()], rdap=FakeRdap(), cache=None
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.ipinfo_lite = IpinfoLiteProvider(token="test-token", timeout=2.0)
        c.app.state.resolve_ip = lambda request: "9.9.9.9"
        with respx.mock:
            respx.get("https://api.ipinfo.io/lite/8.8.8.8").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "ip": "8.8.8.8",
                        "asn": "AS15169",
                        "as_name": "Google LLC",
                        "as_domain": "google.com",
                        "country_code": "US",
                        "country": "United States",
                        "continent_code": "NA",
                        "continent": "North America",
                    },
                )
            )
            r = c.get("/api/providers/ipinfo-lite", params={"ip": "8.8.8.8"})
            assert r.status_code == 200
            data = r.json()
            assert data["provider_id"] == "ipinfo_lite"
            assert data["asn"] == "AS15169"
            assert data["country_code"] == "US"
            assert data["error"] is None


def test_ipinfo_lite_proxy_not_configured():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()], rdap=FakeRdap(), cache=None
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.ipinfo_lite = None
        c.app.state.resolve_ip = lambda request: "9.9.9.9"
        r = c.get("/api/providers/ipinfo-lite", params={"ip": "8.8.8.8"})
        assert r.status_code == 503


def test_ipinfo_lite_proxy_invalid_ip():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()], rdap=FakeRdap(), cache=None
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.ipinfo_lite = None
        c.app.state.resolve_ip = lambda request: "9.9.9.9"
        r = c.get("/api/providers/ipinfo-lite", params={"ip": "nope"})
        assert r.status_code == 400
