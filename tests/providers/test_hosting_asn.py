from pathlib import Path

from app.providers.hosting_asn import HostingAsnIndex


def test_load_and_contains(tmp_path: Path):
    p = tmp_path / "asns.txt"
    p.write_text("AS16509\nAS13335\n# comment\ninvalid\n", encoding="utf-8")
    idx = HostingAsnIndex(path=p)
    assert idx.contains(16509)
    assert idx.contains("AS13335")
    assert idx.contains("13335")
    assert not idx.contains(1)
    assert len(idx) == 2


def test_from_set():
    idx = HostingAsnIndex(asns={15169})
    assert idx.contains("AS15169")
