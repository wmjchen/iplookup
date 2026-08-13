from ipaddress import IPv4Address, IPv4Network

from app.blocklists.source import IpNetsetData, IpNetsetSource, HostsFileSource, HostsData


class ConcreteIpSource(IpNetsetSource):
    source_id = "test_ip"
    category = "test"
    severity = 10
    kind = "ip"
    refresh_ttl = 3600
    url = "http://example.invalid/test.txt"


class ConcreteHostsSource(HostsFileSource):
    source_id = "test_hosts"
    category = "test"
    severity = 10
    kind = "domain"
    refresh_ttl = 86400
    url = "http://example.invalid/hosts.txt"


def test_ipnetset_parse_mixed_ips_and_cidrs():
    src = ConcreteIpSource()
    raw = b"""# comment
1.2.3.4
10.0.0.0/8
2001:db8::1
2001:db8::/32

# trailing comment
"""
    data = src.parse(raw)
    assert IPv4Address("1.2.3.4") in data.ips_v4
    assert IPv4Network("10.0.0.0/8") in data.nets_v4
    assert len(data.nets_v4) == 1
    assert len(data.ips_v4) == 1


def test_ipnetset_matches_ip_single():
    src = ConcreteIpSource()
    data = IpNetsetData(
        ips_v4={IPv4Address("1.2.3.4")}, nets_v4=[],
        ips_v6=set(), nets_v6=[], details={},
    )
    assert src.matches_ip("1.2.3.4", data) == "1.2.3.4"
    assert src.matches_ip("5.6.7.8", data) is None


def test_ipnetset_matches_ip_cidr():
    src = ConcreteIpSource()
    data = IpNetsetData(
        ips_v4=set(), nets_v4=[IPv4Network("10.0.0.0/8")],
        ips_v6=set(), nets_v6=[], details={},
    )
    assert src.matches_ip("10.1.2.3", data) == "10.0.0.0/8"
    assert src.matches_ip("11.0.0.1", data) is None


def test_ipnetset_matches_with_detail():
    src = ConcreteIpSource()
    data = IpNetsetData(
        ips_v4={IPv4Address("1.2.3.4")}, nets_v4=[],
        ips_v6=set(), nets_v6=[],
        details={IPv4Address("1.2.3.4"): "VPN provider: mullvad"},
    )
    assert src.matches_ip("1.2.3.4", data) == "VPN provider: mullvad"


def test_hosts_parse():
    src = ConcreteHostsSource()
    raw = b"""# header
0.0.0.0 adware.example.com
0.0.0.0 tracker.example.com

127.0.0.1 localhost
"""
    data = src.parse(raw)
    assert "adware.example.com" in data.domains
    assert "tracker.example.com" in data.domains
    assert "localhost" in data.domains


def test_hosts_matches_exact_and_suffix():
    src = ConcreteHostsSource()
    data = HostsData(domains={"badguy.com"})
    assert src.matches_domain("badguy.com", data) == "badguy.com"
    assert src.matches_domain("x.badguy.com", data) == "badguy.com"
    assert src.matches_domain("notbadguy.com", data) is None
    assert src.matches_domain("com", data) is None  # don't match TLD only


def test_source_base_homepage_lookup_url_defaults():
    assert ConcreteIpSource().homepage == ""
    assert ConcreteIpSource().lookup_url is None
    assert ConcreteHostsSource().homepage == ""
    assert ConcreteHostsSource().lookup_url is None


def test_lookup_url_for_substitutes_and_encodes_value():
    src = ConcreteIpSource()
    assert src.lookup_url_for("1.2.3.4") is None  # no template -> None
    src.lookup_url = "https://example.invalid/q?ip={value}"
    assert src.lookup_url_for("1.2.3.4") == "https://example.invalid/q?ip=1.2.3.4"
    assert src.lookup_url_for("2001:db8::1") == "https://example.invalid/q?ip=2001%3Adb8%3A%3A1"
