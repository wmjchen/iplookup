import pytest

from app.core.models import DnsRecords
from app.services.dns_resolve import resolve_domain


@pytest.mark.asyncio
async def test_resolve_domain_with_fake():
    async def fake(domain: str) -> DnsRecords:
        assert domain == "example.com"
        return DnsRecords(
            domain=domain,
            a=["93.184.216.34"],
            aaaa=["2606:2800:220:1:248:1893:25c8:1946"],
        )

    rec = await resolve_domain("example.com", resolver=fake)
    assert rec.a == ["93.184.216.34"]
    assert len(rec.aaaa) == 1
