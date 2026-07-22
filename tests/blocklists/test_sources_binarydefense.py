from app.blocklists.sources.binarydefense import BinaryDefenseSource


def test_binarydefense_source():
    src = BinaryDefenseSource()
    assert src.source_id == "binarydefense"
    assert src.url == "https://binarydefense.com/banlist.txt"
    assert src.severity == 8
    assert src.category == "attacker"
    assert src.refresh_ttl == 3600
