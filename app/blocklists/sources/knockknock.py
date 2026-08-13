from __future__ import annotations

from app.blocklists.source import IpNetsetSource


class KnockKnockYearSource(IpNetsetSource):
    source_id = "knockknock_year"
    category = "attacker"
    severity = 12
    refresh_ttl = 3600  # 1h; feed regenerates hourly
    url = "https://knock-knock.net/static/ip-blocklist-year.txt"
    homepage = "https://knock-knock.net/blocklist"


class KnockKnockMonthSource(IpNetsetSource):
    source_id = "knockknock_month"
    category = "attacker"
    severity = 12
    refresh_ttl = 3600  # 1h; feed regenerates hourly
    url = "https://knock-knock.net/static/ip-blocklist-month.txt"
    homepage = "https://knock-knock.net/blocklist"
