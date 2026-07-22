import pytest
from fastapi.testclient import TestClient

from app.core.models import BlocklistReport, DnsRecords, ProviderResult, WhoisInfo
from app.core.orchestrator import LookupOrchestrator
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


class FakeBlocklistChecker:
    enabled = True

    async def check(self, *, ip=None, domain=None):
        return BlocklistReport(
            hits=[], checked_at=0.0, source_counts={"test": 1},
            refreshed_at={}, checked_ips=[], checked_domain=None,
        )


class FakeRegistry:
    def summary(self):
        return [{
            "source_id": "test", "category": "attacker", "severity": 10,
            "kind": "ip", "entries": 100, "last_refreshed": 0.0,
            "next_refresh_in": 3600, "last_error": None,
        }]

    def total_entries(self):
        return 100

    def enabled_sources(self):
        return []


async def _async(v):
    return v


async def _fake_dns(domain: str) -> DnsRecords:
    return DnsRecords(
        domain=domain,
        a=["8.8.8.8"],
        aaaa=["2001:4860:4860::8888"],
    )


@pytest.fixture()
def client():
    with TestClient(app) as c:
        c.app.state.orchestrator = LookupOrchestrator(
            providers=[FakeProvider()],
            rdap=FakeRdap(),
            cache=None,
            ptr_resolver=lambda ip: _async("dns.google"),
            dns_resolver=_fake_dns,
            blocklist_checker=FakeBlocklistChecker(),
        )
        c.app.state.rdap = FakeRdap()
        c.app.state.maxmind_loaded = True
        c.app.state.hosting_asn_count = 2
        c.app.state.resolve_ip = lambda request: "8.8.8.8"
        c.app.state.blocklist_checker = FakeBlocklistChecker()
        c.app.state.blocklist_registry = FakeRegistry()
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["browser_sources"] is True
    assert "ipfire" in body
    assert "ip2location" in body
    assert "ipinfo_lite_proxy" in body


def test_api_ip_text(client):
    r = client.get("/api/ip")
    assert r.status_code == 200
    assert r.text == "8.8.8.8"


def test_api_ip_json(client):
    r = client.get("/api/ip", headers={"accept": "application/json"})
    assert r.status_code == 200
    assert r.json()["ip"] == "8.8.8.8"


def test_lookup_self(client):
    r = client.get("/api/lookup")
    assert r.status_code == 200
    data = r.json()
    assert data["query"] == "8.8.8.8"
    assert data["primary"]["asn"] == "AS15169"
    assert data["risk_score"] >= 40
    assert data["map"]["lat"] == 37.4


def test_lookup_invalid(client):
    r = client.get("/api/lookup", params={"q": "not a host!!!"})
    assert r.status_code == 400


def test_lookup_private(client):
    r = client.get("/api/lookup", params={"ip": "10.0.0.1"})
    assert r.status_code == 200
    data = r.json()
    assert data["classification"]["address_class"] == "private"
    assert data["risk_score"] == 0


def test_lookup_domain(client):
    r = client.get("/api/lookup", params={"q": "google.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["query_type"] == "domain"
    assert data["domain"] == "google.com"
    assert data["query"] == "8.8.8.8"
    assert data["ip_version"] == 4
    assert data["dns"]["a"] == ["8.8.8.8"]
    assert data["dns"]["aaaa"]
    # IPv6 is also fully looked up, not only listed in DNS
    assert len(data["related"]) == 1
    assert data["related"][0]["query"] == "2001:4860:4860::8888"
    assert data["related"][0]["ip_version"] == 6


def test_lookup_domain_prefer_aaaa(client):
    r = client.get("/api/lookup", params={"q": "google.com", "prefer": "aaaa"})
    assert r.status_code == 200
    data = r.json()
    assert data["query"] == "2001:4860:4860::8888"
    assert data["ip_version"] == 6
    assert len(data["related"]) == 1
    assert data["related"][0]["query"] == "8.8.8.8"
    assert data["related"][0]["ip_version"] == 4


def test_resolve_domain(client):
    r = client.get("/api/resolve", params={"q": "example.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["query_type"] == "domain"
    assert data["a"] == ["8.8.8.8"]


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "iplookup" in r.text
    assert "Sources" in r.text


def test_lookup_path_ip(client):
    """Path-based alias /api/lookup/{query} behaves like ?q=."""
    r = client.get("/api/lookup/8.8.8.8")
    assert r.status_code == 200
    data = r.json()
    assert data["query"] == "8.8.8.8"
    assert data["primary"]["asn"] == "AS15169"


def test_lookup_path_domain(client):
    r = client.get("/api/lookup/google.com")
    assert r.status_code == 200
    data = r.json()
    assert data["query_type"] == "domain"
    assert data["domain"] == "google.com"
    assert data["dns"]["a"] == ["8.8.8.8"]


def test_lookup_path_domain_prefer_aaaa(client):
    r = client.get("/api/lookup/google.com", params={"prefer": "aaaa"})
    assert r.status_code == 200
    data = r.json()
    assert data["query"] == "2001:4860:4860::8888"
    assert data["ip_version"] == 6


def test_lookup_page_serves_html(client):
    """GET /{query} serves the SPA HTML for path-based lookup URLs."""
    r = client.get("/8.8.8.8")
    assert r.status_code == 200
    assert "iplookup" in r.text
    assert "Sources" in r.text


def test_lookup_page_domain(client):
    r = client.get("/google.com")
    assert r.status_code == 200
    assert "iplookup" in r.text


def test_health_not_shadowed_by_catch_all(client):
    """/{query} is registered last; /health (single segment) must still win."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_docs_not_shadowed_by_catch_all(client):
    r = client.get("/docs")
    assert r.status_code == 200


def test_openapi_not_shadowed(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


def test_api_blocklists(client):
    r = client.get("/api/blocklists")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert isinstance(body["sources"], list)
    for s in body["sources"]:
        assert "source_id" in s
        assert "category" in s
        assert "severity" in s
        assert "kind" in s
        assert "entries" in s
        assert "last_refreshed" in s
        assert "next_refresh_in" in s
        assert "last_error" in s


def test_api_blocklists_refresh_no_token_404(client):
    r = client.get("/api/blocklists/refresh", params={"source_id": "any"})
    assert r.status_code == 404


def test_api_blocklists_refresh_wrong_token_404(client, monkeypatch):
    monkeypatch.setenv("BLOCKLISTS_ADMIN_TOKEN", "secret")
    r = client.get("/api/blocklists/refresh",
                   params={"source_id": "any", "token": "wrong"})
    assert r.status_code == 404


def test_health_includes_blocklists_field(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert "blocklists" in body
    assert body["blocklists"]["enabled"] is True


def test_api_blocklists_offline_mode(monkeypatch, tmp_path):
    """Verify offline mode (no fetches) still produces a working /api/blocklists.

    With an empty data_dir and refresh_on_startup=False, no fetch runs and no
    cache files exist to load — so every source starts at 0 entries.
    """
    monkeypatch.setenv("BLOCKLISTS_OFFLINE_MODE", "true")
    monkeypatch.setenv("BLOCKLISTS_REFRESH_ON_STARTUP", "false")
    monkeypatch.setenv("BLOCKLISTS_DATA_DIR", str(tmp_path / "blocklists"))
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        with TestClient(app) as c:
            r = c.get("/api/blocklists")
            assert r.status_code == 200
            body = r.json()
            assert body["enabled"] is True
            # All sources are registered but have zero entries (no fetch ran,
            # no cache file existed for load_disk_cache to pick up).
            for s in body["sources"]:
                assert s["entries"] == 0
                assert s["last_refreshed"] is None
    finally:
        get_settings.cache_clear()  # reset for other tests
