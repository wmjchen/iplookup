from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    data_dir: Path = ROOT / "data"
    city_db: Path | None = None
    asn_db: Path | None = None
    country_db: Path | None = None
    hosting_asn_file: Path | None = None
    ip_index_db: Path | None = None
    ipfire_db: Path | None = None
    ip2location_db: Path | None = None
    ipinfo_token: str | None = None

    trust_proxy: bool = True
    provider_timeout_ms: int = 1200
    lookup_deadline_ms: int = 2500
    cache_ttl_seconds: int = 600
    rate_limit_per_minute: int = 45

    enable_maxmind: bool = True
    enable_ip_index: bool = True
    # ip-api is served via /api/providers/ip-api (server proxy + client IP headers).
    # Not added to the orchestrator multi-provider fan-out by default.
    enable_ip_api_proxy: bool = True
    enable_ipwhois: bool = False
    enable_hosting_asn: bool = True
    enable_blocklists: bool = True
    blocklists_data_dir: Path | None = None
    blocklists_extra_sources: str = ""
    blocklists_refresh_on_startup: bool = True
    blocklists_offline_mode: bool = False
    blocklists_user_agent: str = "iplookup/0.1 (blocklist-lookup)"
    blocklists_refresh_timeout_ms: int = 30000
    blocklists_admin_token: str = ""
    enable_ipfire: bool = True
    enable_ip2location: bool = True
    enable_ipinfo_lite: bool = True

    def resolved_city_db(self) -> Path:
        return self.city_db or (self.data_dir / "GeoLite2-City.mmdb")

    def resolved_asn_db(self) -> Path:
        return self.asn_db or (self.data_dir / "GeoLite2-ASN.mmdb")

    def resolved_country_db(self) -> Path:
        return self.country_db or (self.data_dir / "GeoLite2-Country.mmdb")

    def resolved_hosting_asn_file(self) -> Path:
        return self.hosting_asn_file or (self.data_dir / "hosting-asns.txt")

    def resolved_ip_index_db(self) -> Path:
        return self.ip_index_db or (self.data_dir / "ip-index.mmdb")

    def resolved_blocklists_dir(self) -> Path:
        return self.blocklists_data_dir or (self.data_dir / "blocklists")

    def blocklists_extra_sources_list(self) -> list[str]:
        return [
            s.strip().lower()
            for s in (self.blocklists_extra_sources or "").split(",")
            if s.strip()
        ]

    def resolved_ipfire_db(self) -> Path:
        if self.ipfire_db:
            return self.ipfire_db
        for name in ("location.db.xz", "location.db"):
            candidate = self.data_dir / name
            if candidate.exists():
                return candidate
        return self.data_dir / "location.db.xz"

    def resolved_ip2location_db(self) -> Path:
        if self.ip2location_db:
            return self.ip2location_db
        default = self.data_dir / "IP2LOCATION-LITE-DB11.BIN"
        if default.exists():
            return default
        candidates = sorted(self.data_dir.glob("IP2LOCATION*.BIN"))
        return candidates[0] if candidates else default


@lru_cache
def get_settings() -> Settings:
    return Settings()
