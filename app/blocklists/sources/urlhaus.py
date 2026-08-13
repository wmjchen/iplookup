from __future__ import annotations

import csv
import io
from ipaddress import ip_address
from urllib.parse import urlparse

from app.blocklists.source import HostsData, HostsFileSource


class UrlhausHostnamesSource(HostsFileSource):
    source_id = "urlhaus_hostnames"
    category = "malware_c2"
    severity = 20
    refresh_ttl = 3600  # 1h
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    homepage = "https://urlhaus.abuse.ch/"
    lookup_url = "https://urlhaus.abuse.ch/host/{value}/"

    def parse(self, raw: bytes) -> HostsData:
        data = HostsData()
        text = raw.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            url = row[2]
            try:
                host = urlparse(url).hostname
            except ValueError:
                continue
            if host and not _is_ip(host):
                data.domains.add(host.lower())
        return data


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False
