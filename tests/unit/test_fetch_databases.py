import base64
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import fetch_databases as fd


def _tar_with_mmdb(name: str = "GeoLite2-City_20260101/GeoLite2-City.mmdb") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"\x00" * 16
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_fetch_maxmind_uses_basic_auth_and_new_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(fd, "DATA", tmp_path)
    account_id = "1378031"
    license_key = "test-license-key"
    expected_auth = "Basic " + base64.b64encode(
        f"{account_id}:{license_key}".encode()
    ).decode()
    seen: list[object] = []

    class FakeResp:
        def __init__(self, body: bytes):
            self._body = body
            self._pos = 0

        def read(self, n: int = -1) -> bytes:
            if self._pos >= len(self._body):
                return b""
            if n < 0:
                chunk = self._body[self._pos :]
                self._pos = len(self._body)
                return chunk
            chunk = self._body[self._pos : self._pos + n]
            self._pos += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_open(url: str, account_id: str, license_key: str, *, timeout: int = 300):
        seen.append((url, account_id, license_key))
        edition = "City" if "GeoLite2-City" in url else "ASN"
        return FakeResp(_tar_with_mmdb(f"GeoLite2-{edition}_x/GeoLite2-{edition}.mmdb"))

    with patch.object(fd, "_open_maxmind", side_effect=fake_open):
        fd.fetch_maxmind(account_id, license_key)

    assert [u for u, _, _ in seen] == [
        "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
        "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz",
    ]
    assert all(a == account_id and k == license_key for _, a, k in seen)
    assert (tmp_path / "GeoLite2-City.mmdb").is_file()
    assert (tmp_path / "GeoLite2-ASN.mmdb").is_file()

    # _open_maxmind itself builds Basic auth on the request
    recorded: list = []

    class FakeOpener:
        def open(self, req, timeout=300):
            recorded.append(req)
            return FakeResp(_tar_with_mmdb())

    with patch("urllib.request.build_opener", return_value=FakeOpener()):
        with fd._open_maxmind(
            "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
            account_id,
            license_key,
        ):
            pass

    assert len(recorded) == 1
    assert recorded[0].get_header("Authorization") == expected_auth
    assert "license_key" not in recorded[0].full_url


def test_main_requires_account_id_and_license_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(fd, "DATA", tmp_path)
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "only-key")
    monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("GEOIPUPDATE_ACCOUNT_ID", raising=False)

    with (
        patch.object(fd, "fetch_ip_index"),
        patch.object(fd, "fetch_ipfire"),
        patch.object(fd, "fetch_maxmind") as mock_mm,
    ):
        code = fd.main()

    mock_mm.assert_not_called()
    assert code == 0
