from app.api.routes import _domain_targets
from app.core.models import DnsRecords


def test_both_families_default_a_primary():
    dns = DnsRecords(
        domain="google.com",
        a=["8.8.8.8", "8.8.4.4"],
        aaaa=["2001:4860:4860::8888", "2001:4860:4860::8844"],
    )
    assert _domain_targets(dns, "a") == [
        "8.8.8.8",
        "2001:4860:4860::8888",
    ]


def test_prefer_aaaa_primary_still_includes_v4():
    dns = DnsRecords(
        domain="google.com",
        a=["8.8.8.8"],
        aaaa=["2001:4860:4860::8888"],
    )
    assert _domain_targets(dns, "aaaa") == [
        "2001:4860:4860::8888",
        "8.8.8.8",
    ]


def test_only_aaaa():
    dns = DnsRecords(domain="v6.example", a=[], aaaa=["2001:db8::1"])
    assert _domain_targets(dns, "a") == ["2001:db8::1"]


def test_only_a():
    dns = DnsRecords(domain="v4.example", a=["1.2.3.4"], aaaa=[])
    assert _domain_targets(dns, "a") == ["1.2.3.4"]
