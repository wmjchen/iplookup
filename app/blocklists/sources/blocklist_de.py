from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class BlocklistDeSource(IpNetsetSource):
    source_id = "blocklist_de"
    category = "attacker"
    severity = 12
    refresh_ttl = 3600  # 1h
    url = "https://lists.blocklist.de/lists/all.txt"
    homepage = "https://www.blocklist.de/en/index.html"
    lookup_url = "https://www.blocklist.de/en/search.html?ip={value}"
