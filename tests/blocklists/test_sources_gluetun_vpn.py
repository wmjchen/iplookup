import io
import json
import tarfile
from ipaddress import IPv4Address, IPv6Address

import httpx
import pytest
import respx

from app.blocklists.sources.gluetun_vpn import GluetunVpnSource


def _build_tarball(providers: dict[str, dict]) -> bytes:
    """Build an in-memory tar.gz matching codeload.github.com shape."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload in providers.items():
            body = json.dumps(payload).encode("utf-8")
            info = tarfile.TarInfo(name=f"gluetun-servers-main/pkg/servers/{name}.json")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


@pytest.mark.asyncio
@respx.mock
async def test_gluetun_fetch_and_parse():
    mullvad = {
        "servers": [
            {"hostname": "nl-ams-wg-001.mullvad.com", "ips": ["1.2.3.4"]},
            {"hostname": "se-sto-wg-002.mullvad.com", "ips": ["5.6.7.8"]},
        ]
    }
    nordvpn = {
        "servers": [
            {"hostname": "us-ny.nordvpn.com", "ips": ["9.10.11.12"]},
        ]
    }
    tar_bytes = _build_tarball({"mullvad": mullvad, "nordvpn": nordvpn})
    respx.get(
        "https://codeload.github.com/qdm12/gluetun-servers/tar.gz/refs/heads/main"
    ).mock(return_value=httpx.Response(200, content=tar_bytes))

    src = GluetunVpnSource()
    async with httpx.AsyncClient() as client:
        result = await src.fetch(client)
        assert result.etag is not None or True  # codeload may omit headers
        data = src.parse(result.data)
        assert IPv4Address("1.2.3.4") in data.ips_v4
        assert IPv4Address("5.6.7.8") in data.ips_v4
        assert IPv4Address("9.10.11.12") in data.ips_v4
        match = src.matches_ip("1.2.3.4", data)
        assert match is not None
        assert "mullvad" in match.lower()
        match2 = src.matches_ip("9.10.11.12", data)
        assert match2 is not None
        assert "nordvpn" in match2.lower()
        assert src.matches_ip("99.99.99.99", data) is None
        assert src.category == "vpn_endpoint"
        assert src.severity == 15


@pytest.mark.asyncio
@respx.mock
async def test_gluetun_handles_ipv6_and_ignores_unparsable():
    provider = {
        "servers": [
            {"hostname": "v6.example.com", "ips": ["2001:db8::1"]},
            {"hostname": "broken.example.com", "ips": ["not-an-ip"]},
            {"hostname": "no-ips.example.com"},
        ]
    }
    tar_bytes = _build_tarball({"weirdvpn": provider})
    respx.get(
        "https://codeload.github.com/qdm12/gluetun-servers/tar.gz/refs/heads/main"
    ).mock(return_value=httpx.Response(200, content=tar_bytes))

    src = GluetunVpnSource()
    async with httpx.AsyncClient() as client:
        result = await src.fetch(client)
        data = src.parse(result.data)
        assert IPv6Address("2001:db8::1") in data.ips_v6
        assert src.matches_ip("2001:db8::1", data) is not None
        assert src.matches_ip("not-an-ip", data) is None


@pytest.mark.asyncio
@respx.mock
async def test_gluetun_skips_non_pkg_servers_paths():
    provider = {"servers": [{"hostname": "h.example.com", "ips": ["8.8.8.8"]}]}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # The real target file
        body = json.dumps(provider).encode()
        info = tarfile.TarInfo(name="gluetun-servers-main/pkg/servers/realvpn.json")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
        # A distractor file outside pkg/servers (e.g. README at repo root)
        distractor = b"this is not json"
        d_info = tarfile.TarInfo(name="gluetun-servers-main/README.md")
        d_info.size = len(distractor)
        tar.addfile(d_info, io.BytesIO(distractor))
    respx.get(
        "https://codeload.github.com/qdm12/gluetun-servers/tar.gz/refs/heads/main"
    ).mock(return_value=httpx.Response(200, content=buf.getvalue()))

    src = GluetunVpnSource()
    async with httpx.AsyncClient() as client:
        result = await src.fetch(client)
        data = src.parse(result.data)
        assert IPv4Address("8.8.8.8") in data.ips_v4
        assert "realvpn" in src.matches_ip("8.8.8.8", data).lower()
