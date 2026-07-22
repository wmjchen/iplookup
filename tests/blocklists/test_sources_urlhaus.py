import httpx
import pytest
import respx

from app.blocklists.sources.urlhaus import UrlhausHostnamesSource


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_csv_parse():
    body = """# abuse.ch URLhaus recent
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-07-19","http://evil.example.com/payload","online","2026-07-19","malware_download","mirai","https://urlhaus.abuse.ch/url/1/","reporter1"
"2","2026-07-19","http://1.2.3.4/x","online","2026-07-19","malware_download","mirai","https://urlhaus.abuse.ch/url/2/","reporter2"
"""
    respx.get("https://urlhaus.abuse.ch/downloads/csv_recent/").mock(
        return_value=httpx.Response(200, content=body.encode())
    )
    src = UrlhausHostnamesSource()
    client = httpx.AsyncClient()
    try:
        result = await src.fetch(client)
        data = src.parse(result.data)
        assert "evil.example.com" in data.domains
        # IP-only URLs shouldn't pollute the domains set
        assert len(data.domains) == 1
        assert src.matches_domain("evil.example.com", data) == "evil.example.com"
        assert src.severity == 20
        assert src.category == "malware_c2"
    finally:
        await client.aclose()
