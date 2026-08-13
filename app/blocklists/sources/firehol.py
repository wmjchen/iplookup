from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class _FireholBase(IpNetsetSource):
    category = "attacker"
    homepage = "https://iplists.firehol.org/"


class FireholLevel1Source(_FireholBase):
    source_id = "firehol_level1"
    severity = 20
    refresh_ttl = 86400
    url = "https://iplists.firehol.org/files/firehol_level1.netset"


class FireholLevel2Source(_FireholBase):
    source_id = "firehol_level2"
    severity = 12
    refresh_ttl = 3600
    url = "https://iplists.firehol.org/files/firehol_level2.netset"


class FireholLevel3Source(_FireholBase):
    source_id = "firehol_level3"
    severity = 8
    refresh_ttl = 3600
    url = "https://iplists.firehol.org/files/firehol_level3.netset"


class FireholDshieldSource(_FireholBase):
    source_id = "firehol_dshield"
    severity = 12
    refresh_ttl = 3600
    url = "https://iplists.firehol.org/files/dshield.netset"


class FireholBruteforceblockerSource(_FireholBase):
    source_id = "firehol_bruteforceblocker"
    severity = 10
    refresh_ttl = 3600
    url = "https://iplists.firehol.org/files/bruteforceblocker.netset"


class IpfireAggressiveSource(_FireholBase):
    source_id = "ipfire_aggressive"
    severity = 10
    refresh_ttl = 3600
    url = "https://iplists.firehol.org/files/ipfire_aggressive.netset"
