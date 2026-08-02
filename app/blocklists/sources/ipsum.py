from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class IpsumSource(IpNetsetSource):
    """stamparm/ipsum - IPs appearing on N+ lists (aggregated from 30+ sources)."""

    category = "attacker"
    refresh_ttl = 86400  # 24h

    def __init__(self, level: int) -> None:
        if level not in {1, 2, 3, 4, 5, 6, 7, 8}:
            raise ValueError(f"invalid ipsum level: {level}")
        self.level = level
        self.source_id = f"ipsum_{level}"
        self.url = f"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{level}.txt"
        self.severity = {1: 5, 2: 8, 3: 18, 4: 20, 5: 22, 6: 24, 7: 25, 8: 25}[level]
