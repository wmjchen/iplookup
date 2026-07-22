from app.blocklists.sources.firehol import (
    FireholLevel1Source, FireholLevel2Source, FireholLevel3Source,
    FireholDshieldSource, FireholBruteforceblockerSource,
    IpfireAggressiveSource,
)


def test_firehol_source_ids():
    assert FireholLevel1Source().source_id == "firehol_level1"
    assert FireholLevel2Source().source_id == "firehol_level2"
    assert FireholLevel3Source().source_id == "firehol_level3"
    assert FireholDshieldSource().source_id == "firehol_dshield"
    assert FireholBruteforceblockerSource().source_id == "firehol_bruteforceblocker"
    assert IpfireAggressiveSource().source_id == "ipfire_aggressive"


def test_firehol_severities():
    assert FireholLevel1Source().severity == 20
    assert FireholLevel2Source().severity == 12
    assert FireholLevel3Source().severity == 8
    assert FireholDshieldSource().severity == 12
    assert FireholBruteforceblockerSource().severity == 10
    assert IpfireAggressiveSource().severity == 10


def test_firehol_level1_parse():
    src = FireholLevel1Source()
    raw = b"""# firehol_level1.netset
1.2.3.4
10.0.0.0/8
2001:db8::/48
"""
    data = src.parse(raw)
    from ipaddress import IPv4Address, IPv4Network, IPv6Network
    assert IPv4Address("1.2.3.4") in data.ips_v4
    assert IPv4Network("10.0.0.0/8") in data.nets_v4
    assert IPv6Network("2001:db8::/48") in data.nets_v6
