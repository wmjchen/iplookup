from app.core.models import BlocklistHit, BlocklistReport, LookupReport


def test_blocklist_hit_defaults():
    hit = BlocklistHit(
        source_id="spamhaus_drop",
        category="hijacked_network",
        severity=25,
        matched_value="1.2.3.4",
    )
    assert hit.detail is None
    assert hit.severity == 25


def test_blocklist_report_defaults():
    rep = BlocklistReport(checked_at=0.0)
    assert rep.hits == []
    assert rep.source_counts == {}
    assert rep.refreshed_at == {}
    assert rep.checked_ips == []
    assert rep.checked_domain is None


def test_lookup_report_has_blocklists_field_default_none():
    rep = LookupReport(query="1.1.1.1", ip_version=4, request_id="abc")
    assert rep.blocklists is None


def test_blocklist_hit_link_defaults():
    hit = BlocklistHit(
        source_id="spamhaus_drop",
        category="hijacked_network",
        severity=25,
        matched_value="1.2.3.4",
    )
    assert hit.homepage is None
    assert hit.lookup_url is None


def test_blocklist_report_source_homepages_default():
    rep = BlocklistReport(checked_at=0.0)
    assert rep.source_homepages == {}
