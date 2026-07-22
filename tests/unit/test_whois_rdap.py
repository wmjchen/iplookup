import httpx
import pytest
import respx

from app.services.whois_rdap import RdapClient


@pytest.mark.asyncio
@respx.mock
async def test_rdap_extract():
    respx.get("https://rdap.org/ip/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "country": "US",
                "name": "GOGL",
                "handle": "NET-8-8-8-0-1",
                "port43": "whois.arin.net",
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": [
                            "vcard",
                            [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]],
                        ],
                    }
                ],
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2014-03-14T00:00:00Z",
                    }
                ],
                "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
            },
        )
    )
    client = RdapClient()
    try:
        info = await client.lookup("8.8.8.8")
        assert info is not None
        assert info.country == "US"
        assert info.org == "Google LLC"
        assert info.cidr == "8.8.8.0/24"
        assert info.registry == "ARIN"
        assert info.netname == "GOGL"
    finally:
        await client.aclose()
