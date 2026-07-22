from pathlib import Path

import pytest

from app.vendor.pylibloc import LocDB

DATA = Path(__file__).resolve().parents[2] / "data"
LOC_DB = DATA / "location.db.xz"


def test_vendor_module_imports():
    assert callable(LocDB)


@pytest.mark.skipif(not LOC_DB.exists(), reason="location.db.xz missing")
def test_locdb_real_db_known_anycast():
    """Pins pylibloc flag bits against the live DB (1.1.1.1 = Cloudflare anycast)."""
    db = LocDB(str(LOC_DB), debug=0)
    cos, asn, as_name, flags, mask = db.lookup("1.1.1.1")
    assert cos is not None
    assert asn == 13335
    assert flags & 4  # ANYCAST
