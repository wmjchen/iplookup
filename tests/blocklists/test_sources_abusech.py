from app.blocklists.sources.abusech import (
    FeodoSource, AbusechSslblSource, AbusechBogonsSource,
)


def test_abusech_source_ids():
    assert FeodoSource().source_id == "feodo"
    assert AbusechSslblSource().source_id == "abusech_sslbl"
    assert AbusechBogonsSource().source_id == "abusech_bogons"


def test_abusech_severities():
    assert FeodoSource().severity == 20
    assert FeodoSource().category == "malware_c2"
    assert AbusechSslblSource().severity == 15
    assert AbusechBogonsSource().severity == 8


def test_feodo_parse_with_comments():
    src = FeodoSource()
    raw = b"""# Feodo botnet C2 IP blocklist
# Last updated: 2026-07-19
1.2.3.4
5.6.7.8
"""
    data = src.parse(raw)
    from ipaddress import IPv4Address
    assert IPv4Address("1.2.3.4") in data.ips_v4
    assert len(data.ips_v4) == 2
