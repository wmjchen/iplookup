from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class FeodoSource(IpNetsetSource):
    source_id = "feodo"
    category = "malware_c2"
    severity = 20
    refresh_ttl = 3600
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"


class AbusechSslblSource(IpNetsetSource):
    source_id = "abusech_sslbl"
    category = "malware_c2"
    severity = 15
    refresh_ttl = 3600
    url = "https://sslbl.abuse.ch/downloads/sslipblacklist.txt"


class AbusechBogonsSource(IpNetsetSource):
    source_id = "abusech_bogons"
    category = "bogon"
    severity = 8
    refresh_ttl = 3600
    url = "https://feodotracker.abuse.ch/downloads/bogonlist.txt"
