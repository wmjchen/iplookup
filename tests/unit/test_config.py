from app.config import Settings


def test_blocklist_settings_defaults():
    s = Settings()
    assert s.enable_blocklists is True
    assert s.blocklists_refresh_on_startup is True
    assert s.blocklists_offline_mode is False
    assert s.blocklists_user_agent == "iplookup/0.1 (blocklist-lookup)"
    assert s.blocklists_refresh_timeout_ms == 30000
    assert s.blocklists_admin_token == ""
    assert s.blocklists_extra_sources == ""


def test_resolved_blocklists_dir():
    s = Settings()
    p = s.resolved_blocklists_dir()
    assert p.name == "blocklists"
    assert p.parent.name == "data"


def test_extra_sources_parses_to_list():
    s = Settings(blocklists_extra_sources="fakenews,porn")
    assert s.blocklists_extra_sources_list() == ["fakenews", "porn"]


def test_extra_sources_empty():
    s = Settings()
    assert s.blocklists_extra_sources_list() == []


def test_resolved_ipfire_db_prefers_xz(tmp_path):
    (tmp_path / "location.db.xz").touch()
    (tmp_path / "location.db").touch()
    s = Settings(data_dir=tmp_path)
    assert s.resolved_ipfire_db() == tmp_path / "location.db.xz"


def test_resolved_ipfire_db_falls_back_to_uncompressed(tmp_path):
    (tmp_path / "location.db").touch()
    s = Settings(data_dir=tmp_path)
    assert s.resolved_ipfire_db() == tmp_path / "location.db"


def test_resolved_ipfire_db_default_when_absent(tmp_path):
    s = Settings(data_dir=tmp_path)
    assert s.resolved_ipfire_db() == tmp_path / "location.db.xz"


def test_resolved_ipfire_db_explicit_override(tmp_path):
    custom = tmp_path / "custom.db"
    s = Settings(data_dir=tmp_path, ipfire_db=custom)
    assert s.resolved_ipfire_db() == custom


def test_resolved_ip2location_db_default(tmp_path):
    s = Settings(data_dir=tmp_path)
    assert s.resolved_ip2location_db() == tmp_path / "IP2LOCATION-LITE-DB11.BIN"


def test_resolved_ip2location_db_glob_fallback(tmp_path):
    (tmp_path / "IP2LOCATION-LITE-DB11.IPV6.BIN").touch()
    s = Settings(data_dir=tmp_path)
    assert s.resolved_ip2location_db() == tmp_path / "IP2LOCATION-LITE-DB11.IPV6.BIN"
