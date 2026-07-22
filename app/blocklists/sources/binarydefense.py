from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class BinaryDefenseSource(IpNetsetSource):
    source_id = "binarydefense"
    category = "attacker"
    severity = 8
    refresh_ttl = 3600  # 1h
    url = "https://binarydefense.com/banlist.txt"
