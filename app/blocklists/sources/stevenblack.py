from __future__ import annotations

from app.blocklists.source import HostsFileSource

_BASE = "https://raw.githubusercontent.com/StevenBlack/hosts/master"
_CATEGORIES = {None, "adware", "fakenews", "gambling", "porn", "social"}


class StevenblackHostsSource(HostsFileSource):
    """StevenBlack hosts — optionally a category extension."""

    def __init__(self, category: str | None = None) -> None:
        if category not in _CATEGORIES:
            raise ValueError(f"invalid stevenblack category: {category}")
        if category is None:
            self.source_id = "stevenblack_hosts"
            self.url = f"{_BASE}/data/StevenBlack/hosts"
            self.category = "adware"  # unified list is mostly adware
            self.severity = 15
        else:
            self.source_id = f"stevenblack_{category}"
            self.url = f"{_BASE}/extensions/{category}/hosts"
            self.category = category
            self.severity = {
                "adware": 8,
                "fakenews": 10,
                "gambling": 5,
                "porn": 5,
                "social": 5,
            }[category]
        self.refresh_ttl = 86400  # 24h
