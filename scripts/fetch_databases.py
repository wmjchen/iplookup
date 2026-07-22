#!/usr/bin/env python3
"""Download local GeoIP databases into data/ (build/deploy hook).

Free (no token):
  - ip-index.mmdb
  - location.db.xz (IPFire)

Token required (skipped with a warning if unset):
  - GeoLite2 City/ASN via MAXMIND_ACCOUNT_ID + MAXMIND_LICENSE_KEY
  - IP2Location LITE DB11 via IP2LOCATION_DOWNLOAD_TOKEN
"""
from __future__ import annotations

import base64
import os
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("DATA_DIR", ROOT / "data"))

IP_INDEX_URL = (
    "https://github.com/Umkus/ip-index/releases/download/latest/ip-index.mmdb"
)
IPFIRE_URL = "https://location.ipfire.org/databases/1/location.db.xz"
MAXMIND_URL = (
    "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
)
IP2LOCATION_URL = (
    "https://www.ip2location.com/download"
    "?token={token}&file=DB11LITEBINIPV6"
)

UA = "iplookup-fetch-databases/0.1"


class _MaxMindRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow MaxMind → R2 redirects without re-sending auth/extra headers.

    urllib's default redirect handler leaves headers that make R2 signed URLs
    return 400 Missing x-amz-content-sha256.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = super().redirect_request(req, fp, code, msg, headers, newurl)
        if newreq is None:
            return None
        newreq.headers.clear()
        newreq.unredirected_hdrs.clear()
        newreq.add_header("User-Agent", UA)
        return newreq


def _log(msg: str) -> None:
    print(msg, flush=True)


def _download(url: str, dest: Path, *, timeout: int = 300) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with tempfile.NamedTemporaryFile(delete=False, dir=dest.parent) as tmp:
        tmp_path = Path(tmp.name)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    tmp.write(chunk)
            tmp_path.replace(dest)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise


def _open_maxmind(url: str, account_id: str, license_key: str, *, timeout: int = 300):
    auth = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Authorization": f"Basic {auth}",
        },
    )
    opener = urllib.request.build_opener(_MaxMindRedirectHandler)
    return opener.open(req, timeout=timeout)


def fetch_ip_index() -> None:
    dest = DATA / "ip-index.mmdb"
    _log(f"fetching ip-index -> {dest}")
    _download(IP_INDEX_URL, dest)


def fetch_ipfire() -> None:
    dest = DATA / "location.db.xz"
    _log(f"fetching IPFire location -> {dest}")
    _download(IPFIRE_URL, dest)


def fetch_maxmind(account_id: str, license_key: str) -> None:
    for edition, out_name in (
        ("GeoLite2-City", "GeoLite2-City.mmdb"),
        ("GeoLite2-ASN", "GeoLite2-ASN.mmdb"),
    ):
        url = MAXMIND_URL.format(edition=edition)
        _log(f"fetching MaxMind {edition}")
        with tempfile.TemporaryDirectory(dir=DATA) as tmp:
            tar_path = Path(tmp) / f"{edition}.tar.gz"
            with _open_maxmind(url, account_id, license_key) as resp, tar_path.open(
                "wb"
            ) as f:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            with tarfile.open(tar_path, "r:gz") as tar:
                mmdb_member = next(
                    (
                        m
                        for m in tar.getmembers()
                        if m.isfile() and m.name.endswith(".mmdb")
                    ),
                    None,
                )
                if mmdb_member is None:
                    raise RuntimeError(f"no .mmdb in MaxMind archive for {edition}")
                extracted = tar.extractfile(mmdb_member)
                if extracted is None:
                    raise RuntimeError(f"failed to extract {mmdb_member.name}")
                dest = DATA / out_name
                with tempfile.NamedTemporaryFile(
                    delete=False, dir=DATA, suffix=".mmdb"
                ) as out:
                    out.write(extracted.read())
                    Path(out.name).replace(dest)
                _log(f"  wrote {dest}")


def fetch_ip2location(token: str) -> None:
    url = IP2LOCATION_URL.format(token=token)
    _log("fetching IP2Location LITE DB11")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with tempfile.TemporaryDirectory(dir=DATA) as tmp:
        zip_path = Path(tmp) / "db11.zip"
        with urllib.request.urlopen(req, timeout=300) as resp, zip_path.open("wb") as f:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        with zipfile.ZipFile(zip_path) as zf:
            bins = [n for n in zf.namelist() if n.upper().endswith(".BIN")]
            if not bins:
                raise RuntimeError("no .BIN in IP2Location zip")
            # Prefer IPV6 edition filename when present
            bins.sort(key=lambda n: ("IPV6" not in n.upper(), n))
            name = bins[0]
            dest = DATA / Path(name).name
            with zf.open(name) as src, tempfile.NamedTemporaryFile(
                delete=False, dir=DATA, suffix=".BIN"
            ) as out:
                out.write(src.read())
                Path(out.name).replace(dest)
            _log(f"  wrote {dest}")
            for extra in zf.namelist():
                if extra.upper().endswith("LICENSE_LITE.TXT"):
                    lic = DATA / "LICENSE_LITE.TXT"
                    with zf.open(extra) as src, lic.open("wb") as out:
                        out.write(src.read())


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    for label, fn in (("ip-index", fetch_ip_index), ("ipfire", fetch_ipfire)):
        try:
            fn()
        except (urllib.error.URLError, OSError, RuntimeError) as e:
            errors.append(f"{label}: {e}")
            _log(f"ERROR {label}: {e}")

    maxmind_account = (
        os.environ.get("MAXMIND_ACCOUNT_ID")
        or os.environ.get("GEOIPUPDATE_ACCOUNT_ID")
        or ""
    ).strip()
    maxmind_key = (
        os.environ.get("MAXMIND_LICENSE_KEY")
        or os.environ.get("GEOIPUPDATE_LICENSE_KEY")
        or ""
    ).strip()
    if maxmind_account and maxmind_key:
        try:
            fetch_maxmind(maxmind_account, maxmind_key)
        except (urllib.error.URLError, OSError, RuntimeError) as e:
            errors.append(f"maxmind: {e}")
            _log(f"ERROR maxmind: {e}")
    else:
        _log(
            "skip MaxMind (set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY "
            "to fetch GeoLite2)"
        )

    ip2_token = os.environ.get("IP2LOCATION_DOWNLOAD_TOKEN", "").strip()
    if ip2_token:
        try:
            fetch_ip2location(ip2_token)
        except (urllib.error.URLError, OSError, RuntimeError) as e:
            errors.append(f"ip2location: {e}")
            _log(f"ERROR ip2location: {e}")
    else:
        _log("skip IP2Location (set IP2LOCATION_DOWNLOAD_TOKEN to fetch DB11)")

    if errors:
        _log(f"finished with {len(errors)} error(s)")
        return 1
    _log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
