from __future__ import annotations

from app.blocklists.source import IpNetsetData, IpNetsetSource


class _SpamhausBase(IpNetsetSource):
    category = "hijacked_network"
    severity = 25
    refresh_ttl = 86400  # 24h

    def parse(self, raw: bytes) -> IpNetsetData:
        text = raw.decode("utf-8", errors="replace")
        cleaned = "\n".join(line.split(";", 1)[0] for line in text.splitlines())
        return super().parse(cleaned.encode("utf-8"))


class SpamhausDropSource(_SpamhausBase):
    source_id = "spamhaus_drop"
    url = "https://www.spamhaus.org/drop/drop.txt"


class SpamhausEdropSource(_SpamhausBase):
    source_id = "spamhaus_edrop"
    url = "https://www.spamhaus.org/drop/edrop.txt"


class SpamhausDropv6Source(_SpamhausBase):
    source_id = "spamhaus_dropv6"
    url = "https://www.spamhaus.org/drop/dropv6.txt"
