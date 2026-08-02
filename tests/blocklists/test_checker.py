import time
from ipaddress import IPv4Address

import pytest

from app.blocklists.checker import BlocklistChecker
from app.blocklists.registry import BlocklistRegistry
from app.blocklists.source import HostsData, IpNetsetData
from app.core.models import BlocklistReport


class _StaticSource:
    """Source that returns preloaded data (no fetch)."""

    def __init__(self, source_id, data, category="attacker", severity=10,
                 kind="ip", refresh_ttl=3600):
        self.source_id = source_id
        self._data = data
        self.category = category
        self.severity = severity
        self.kind = kind
        self.refresh_ttl = refresh_ttl
        self.url = f"http://example.invalid/{source_id}"

    async def fetch(self, client):
        raise RuntimeError("static source - no fetch")

    def parse(self, raw):
        return self._data

    def matches_ip(self, ip, data):
        try:
            addr = IPv4Address(ip)
        except ValueError:
            return None
        if addr in data.ips_v4:
            return data.details.get(addr, str(addr))
        return None

    def matches_domain(self, domain, data):
        d = domain.lower()
        if d in data.domains:
            return d
        return None


@pytest.fixture
def populated_registry(tmp_path):
    ip_data = IpNetsetData(
        ips_v4={IPv4Address("1.2.3.4")}, nets_v4=[],
        ips_v6=set(), nets_v6=[],
        details={IPv4Address("1.2.3.4"): "VPN provider: mullvad"},
    )
    domain_data = HostsData(domains={"badguy.com"})
    sources = [
        _StaticSource("vpn_list", ip_data, category="vpn_endpoint", severity=15),
        _StaticSource("bad_domains", domain_data,
                      category="adware", severity=15, kind="domain"),
    ]
    reg = BlocklistRegistry(data_dir=tmp_path / "bl", sources=sources)
    for s in sources:
        reg._data[s.source_id] = s._data
        reg._last_refreshed[s.source_id] = time.time()
        reg._last_error[s.source_id] = None
    return reg


@pytest.mark.asyncio
async def test_check_ip_hit(populated_registry):
    checker = BlocklistChecker(registry=populated_registry)
    report = await checker.check(ip="1.2.3.4")
    assert isinstance(report, BlocklistReport)
    assert any(h.source_id == "vpn_list" for h in report.hits)
    hit = next(h for h in report.hits if h.source_id == "vpn_list")
    assert hit.category == "vpn_endpoint"
    assert hit.severity == 15
    assert "mullvad" in (hit.detail or "")
    assert "1.2.3.4" in report.checked_ips
    assert "vpn_list" in report.source_counts


@pytest.mark.asyncio
async def test_check_ip_miss(populated_registry):
    checker = BlocklistChecker(registry=populated_registry)
    report = await checker.check(ip="99.99.99.99")
    assert report.hits == []
    assert "99.99.99.99" in report.checked_ips
    assert report.source_counts["vpn_list"] == 1


@pytest.mark.asyncio
async def test_check_domain_hit(populated_registry):
    checker = BlocklistChecker(registry=populated_registry)
    report = await checker.check(domain="badguy.com")
    assert any(h.source_id == "bad_domains" for h in report.hits)
    assert report.checked_domain == "badguy.com"


@pytest.mark.asyncio
async def test_check_combined_ip_and_domain(populated_registry):
    checker = BlocklistChecker(registry=populated_registry)
    report = await checker.check(ip="1.2.3.4", domain="badguy.com")
    sources_hit = {h.source_id for h in report.hits}
    assert "vpn_list" in sources_hit
    assert "bad_domains" in sources_hit


@pytest.mark.asyncio
async def test_check_disabled_returns_empty_report(populated_registry):
    checker = BlocklistChecker(registry=populated_registry, enabled=False)
    report = await checker.check(ip="1.2.3.4")
    assert report.hits == []
    assert report.source_counts == {}
