import pytest

from app.services.ptr import reverse_dns


@pytest.mark.asyncio
async def test_reverse_dns_with_resolver():
    async def fake(ip: str) -> str | None:
        assert ip == "8.8.8.8"
        return "dns.google"

    assert await reverse_dns("8.8.8.8", resolver=fake) == "dns.google"


@pytest.mark.asyncio
async def test_reverse_dns_none():
    async def fake(ip: str) -> str | None:
        return None

    assert await reverse_dns("1.2.3.4", resolver=fake) is None
