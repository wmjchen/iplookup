import pytest

from app.core.cache import TTLCache
from app.core.models import BlocklistHit, BlocklistReport
from app.core.models import LookupReport, ProviderResult, WhoisInfo
from app.core.orchestrator import LookupOrchestrator, pick_primary
from app.services.whois_rdap import RdapClient


class FakeProvider:
    def __init__(self, provider_id: str, result: ProviderResult | Exception | None = None, delay: float = 0):
        self.provider_id = provider_id
        self.result = result
        self.delay = delay

    async def lookup(self, ip: str) -> ProviderResult:
        import asyncio

        if self.delay:
            await asyncio.sleep(self.delay)
        if isinstance(self.result, Exception):
            raise self.result
        if self.result is None:
            return ProviderResult(provider_id=self.provider_id, ip=ip, error="none")
        return self.result.model_copy(update={"ip": ip})


class FakeRdap(RdapClient):
    def __init__(self, info: WhoisInfo | None):
        super().__init__()
        self.info = info

    async def lookup(self, ip: str) -> WhoisInfo | None:
        return self.info


def test_pick_primary_prefers_maxmind():
    sources = [
        ProviderResult(provider_id="ip_api", ip="1.1.1.1", country_code="AU"),
        ProviderResult(provider_id="maxmind", ip="1.1.1.1", country_code="US"),
    ]
    primary = pick_primary(sources)
    assert primary is not None
    assert primary.provider_id == "maxmind"


def test_pick_primary_preferred_db():
    sources = [
        ProviderResult(provider_id="maxmind", ip="1.1.1.1", country_code="US"),
        ProviderResult(provider_id="ip_api", ip="1.1.1.1", country_code="AU"),
    ]
    primary = pick_primary(sources, preferred_db="ip_api")
    assert primary is not None
    assert primary.provider_id == "ip_api"


@pytest.mark.asyncio
async def test_orchestrator_partial_failure():
    good = ProviderResult(
        provider_id="maxmind",
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        city="Mountain View",
        latitude=37.4,
        longitude=-122.1,
        asn="AS15169",
        as_name="GOOGLE",
        is_hosting=True,
    )
    orch = LookupOrchestrator(
        providers=[
            FakeProvider("maxmind", good),
            FakeProvider("ip_api", Exception("boom")),
        ],
        rdap=FakeRdap(WhoisInfo(country="US", org="Google LLC", source="rdap")),
        cache=None,
        ptr_resolver=lambda ip: _async_val("dns.google"),
        provider_timeout=1.0,
    )
    report = await orch.lookup("8.8.8.8", client_ip="8.8.8.8")
    assert isinstance(report, LookupReport)
    assert report.primary is not None
    assert report.primary.provider_id == "maxmind"
    assert report.network.rdns == "dns.google"
    assert report.classification.ip_type == "native"
    assert report.classification.usage == "hosting"
    assert report.risk_score >= 40
    assert report.map is not None
    assert any(s.error for s in report.sources)


@pytest.mark.asyncio
async def test_orchestrator_quad9_not_residential():
    quad = ProviderResult(
        provider_id="maxmind",
        ip="9.9.9.9",
        country="United States",
        country_code="US",
        asn="AS19281",
        as_name="Quad9",
        isp="Quad9",
        org="Quad9",
        is_hosting=False,
    )
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", quad)],
        rdap=FakeRdap(None),
        cache=None,
        ptr_resolver=lambda ip: _async(None),
    )
    report = await orch.lookup("9.9.9.9")
    assert report.classification.usage == "hosting"
    assert report.risk_score >= 40
    assert "infra_asn" in report.classification.proxy_signals or (
        "infra_keyword" in report.classification.proxy_signals
    )


async def _async_val(v):
    return v


@pytest.mark.asyncio
async def test_orchestrator_private_ip():
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", Exception("should not run"))],
        rdap=FakeRdap(None),
        cache=None,
        provider_timeout=0.5,
    )
    report = await orch.lookup("10.0.0.1")
    assert report.classification.address_class == "private"
    assert report.risk_score == 0
    assert report.sources == []


@pytest.mark.asyncio
async def test_orchestrator_cache():
    good = ProviderResult(
        provider_id="maxmind",
        ip="1.1.1.1",
        country_code="AU",
        latitude=-27.0,
        longitude=153.0,
    )
    cache: TTLCache[LookupReport] = TTLCache(ttl_seconds=60)
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", good)],
        rdap=FakeRdap(None),
        cache=cache,
        ptr_resolver=lambda ip: _async_val(None),
    )
    r1 = await orch.lookup("1.1.1.1")
    assert r1.cached is False
    r2 = await orch.lookup("1.1.1.1")
    assert r2.cached is True


class FakeBlocklistChecker:
    """Test double - returns a pre-baked report regardless of input."""

    def __init__(self, report: BlocklistReport | None = None):
        self.report = report or BlocklistReport(
            hits=[], checked_at=0.0, source_counts={"test": 1}, refreshed_at={},
            checked_ips=[], checked_domain=None,
        )
        self.enabled = True

    async def check(self, *, ip=None, domain=None):
        return self.report.model_copy()


@pytest.mark.asyncio
async def test_orchestrator_runs_blocklist_check():
    good = ProviderResult(
        provider_id="maxmind", ip="8.8.8.8", country_code="US",
        city="Mountain View", latitude=37.4, longitude=-122.1,
        asn="AS15169", as_name="GOOGLE", is_hosting=True,
    )
    bl_report = BlocklistReport(
        hits=[BlocklistHit(
            source_id="tor_bulk_exit", category="tor_exit", severity=18,
            matched_value="8.8.8.8",
        )],
        checked_at=0.0,
        source_counts={"tor_bulk_exit": 921},
        refreshed_at={"tor_bulk_exit": 0.0},
        checked_ips=["8.8.8.8"],
        checked_domain=None,
    )
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", good)],
        rdap=FakeRdap(None),
        cache=None,
        ptr_resolver=lambda ip: _async_val(None),
        blocklist_checker=FakeBlocklistChecker(report=bl_report),
    )
    report = await orch.lookup("8.8.8.8", client_ip="8.8.8.8")
    assert report.blocklists is not None
    assert any(h.source_id == "tor_bulk_exit" for h in report.blocklists.hits)
    assert "tor_exit" in report.classification.proxy_signals
    assert report.risk_score >= 58  # 40 hosting + 18 tor_exit


@pytest.mark.asyncio
async def test_orchestrator_no_blocklist_checker_means_none():
    good = ProviderResult(
        provider_id="maxmind", ip="8.8.8.8", country_code="US",
        latitude=37.4, longitude=-122.1, is_hosting=True,
    )
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", good)],
        rdap=FakeRdap(None),
        cache=None,
        ptr_resolver=lambda ip: _async_val(None),
        blocklist_checker=None,
    )
    report = await orch.lookup("8.8.8.8")
    assert report.blocklists is None


@pytest.mark.asyncio
async def test_orchestrator_vpn_hit_promotes_proxy_signal():
    good = ProviderResult(
        provider_id="maxmind", ip="1.1.1.1", country_code="AU",
        latitude=-27.0, longitude=153.0, is_hosting=False, is_proxy=False,
    )
    bl_report = BlocklistReport(
        hits=[BlocklistHit(
            source_id="gluetun_vpn", category="vpn_endpoint", severity=15,
            detail="VPN provider: mullvad", matched_value="1.1.1.1",
        )],
        checked_at=0.0, source_counts={"gluetun_vpn": 1}, refreshed_at={},
        checked_ips=["1.1.1.1"], checked_domain=None,
    )
    orch = LookupOrchestrator(
        providers=[FakeProvider("maxmind", good)],
        rdap=FakeRdap(None),
        cache=None,
        ptr_resolver=lambda ip: _async_val(None),
        blocklist_checker=FakeBlocklistChecker(report=bl_report),
    )
    report = await orch.lookup("1.1.1.1")
    assert "vpn_endpoint" in report.classification.proxy_signals
