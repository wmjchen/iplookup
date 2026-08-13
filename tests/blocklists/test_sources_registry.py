from app.blocklists.sources import all_sources, default_source_ids, default_off_source_ids


def test_all_sources_register():
    sources = all_sources()
    ids = {s.source_id for s in sources}
    assert "spamhaus_drop" in ids
    assert "tor_bulk_exit" in ids
    assert "tor_consensus" in ids
    assert "gluetun_vpn" in ids
    assert "ipsum_3" in ids
    assert "stevenblack_hosts" in ids
    assert "urlhaus_hostnames" in ids


def test_default_on_count():
    assert len(default_source_ids()) == 14


def test_default_off_count():
    assert len(default_off_source_ids()) == 13


def test_no_overlap_default_on_off():
    on = default_source_ids()
    off = default_off_source_ids()
    assert on.isdisjoint(off)


def test_total_source_count():
    assert len(default_source_ids()) + len(default_off_source_ids()) == 27


def test_ipsum_levels_distinct():
    sources = all_sources()
    ids = {s.source_id for s in sources}
    assert "ipsum_3" in ids
    assert "ipsum_5" in ids


def test_stevenblack_categories_distinct():
    sources = all_sources()
    ids = {s.source_id for s in sources}
    assert "stevenblack_hosts" in ids
    assert "stevenblack_adware" in ids
    assert "stevenblack_fakenews" in ids
    assert "stevenblack_gambling" in ids
    assert "stevenblack_porn" in ids
    assert "stevenblack_social" in ids


def test_all_sources_have_homepage():
    for s in all_sources():
        assert s.homepage, f"{s.source_id} must define a homepage"


def test_known_lookup_urls_resolve():
    by_id = {s.source_id: s for s in all_sources()}
    assert by_id["spamhaus_drop"].lookup_url_for("1.2.3.4") == (
        "https://www.spamhaus.org/query/bl?ip=1.2.3.4"
    )
    assert by_id["spamhaus_edrop"].lookup_url_for("1.2.3.4") == (
        "https://www.spamhaus.org/query/bl?ip=1.2.3.4"
    )
    assert by_id["blocklist_de"].lookup_url_for("1.2.3.4") == (
        "https://www.blocklist.de/en/search.html?ip=1.2.3.4"
    )
    assert by_id["feodo"].lookup_url_for("1.2.3.4") == (
        "https://feodotracker.abuse.ch/browse/host/1.2.3.4/"
    )
    assert by_id["urlhaus_hostnames"].lookup_url_for("badguy.com") == (
        "https://urlhaus.abuse.ch/host/badguy.com/"
    )
