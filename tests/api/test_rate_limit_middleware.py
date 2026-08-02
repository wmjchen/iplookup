import pytest
from fastapi.testclient import TestClient

from app.core.models import DnsRecords, ProviderResult, WhoisInfo
from app.core.orchestrator import LookupOrchestrator
from app.core.rate_limit import RateLimiter, path_is_rate_limited
from app.main import app
from app.services.whois_rdap import RdapClient


class FakeProvider:
    provider_id = "maxmind"

    async def lookup(self, ip: str) -> ProviderResult:
        return ProviderResult(
            provider_id="maxmind",
            ip=ip,
            country="United States",
            country_code="US",
            city="Mountain View",
            latitude=37.4,
            longitude=-122.1,
            asn="AS15169",
            as_name="GOOGLE",
            is_hosting=True,
        )


class FakeRdap(RdapClient):
    async def lookup(self, ip: str) -> WhoisInfo | None:
        return WhoisInfo(country="US", org="Google LLC", source="rdap", netname="GOGL")


async def _async(v):
    return v


async def _fake_dns(domain: str) -> DnsRecords:
    return DnsRecords(domain=domain, a=["8.8.8.8"], aaaa=[])


@pytest.fixture()
def client():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()],
            rdap=FakeRdap(),
            cache=None,
            ptr_resolver=lambda ip: _async("dns.google"),
            dns_resolver=_fake_dns,
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.maxmind_loaded = True
        c.app.state.hosting_asn_count = 2
        c.app.state.resolve_ip = lambda request: "203.0.113.10"
        c.app.state.rate_limiter = RateLimiter(max_requests=2, window_seconds=60)
        yield c


def test_lookup_rate_limited_after_limit(client):
    assert client.get("/api/lookup?q=8.8.8.8").status_code == 200
    assert client.get("/api/lookup?q=8.8.8.8").status_code == 200
    r = client.get("/api/lookup?q=8.8.8.8")
    assert r.status_code == 429
    assert r.json()["detail"] == "rate limit exceeded"
    assert "Retry-After" in r.headers
    assert int(r.headers["Retry-After"]) >= 1


def test_health_not_rate_limited(client):
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_api_ip_not_rate_limited(client):
    for _ in range(5):
        assert client.get("/api/ip").status_code == 200


def test_rate_limit_headers_on_success(client):
    r = client.get("/api/lookup?q=8.8.8.8")
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert r.headers["X-RateLimit-Remaining"] == "1"


def test_path_is_rate_limited_blocklists_refresh():
    # Admin refresh endpoint hits upstreams - must be rate-limited (spec §9).
    assert path_is_rate_limited("/api/blocklists/refresh") is True
    # Read-only status endpoint is NOT rate-limited (has its own 60s Cache-Control).
    assert path_is_rate_limited("/api/blocklists") is False
