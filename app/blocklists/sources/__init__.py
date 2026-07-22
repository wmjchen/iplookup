"""Concrete blocklist source implementations + registry helpers."""

from __future__ import annotations

from app.blocklists.source import BlocklistSource
from app.blocklists.sources.abusech import (
    AbusechBogonsSource, AbusechSslblSource, FeodoSource,
)
from app.blocklists.sources.binarydefense import BinaryDefenseSource
from app.blocklists.sources.blocklist_de import BlocklistDeSource
from app.blocklists.sources.firehol import (
    FireholBruteforceblockerSource, FireholDshieldSource,
    FireholLevel1Source, FireholLevel2Source, FireholLevel3Source,
    IpfireAggressiveSource,
)
from app.blocklists.sources.gluetun_vpn import GluetunVpnSource
from app.blocklists.sources.ipsum import IpsumSource
from app.blocklists.sources.spamhaus import (
    SpamhausDropSource, SpamhausDropv6Source, SpamhausEdropSource,
)
from app.blocklists.sources.stevenblack import StevenblackHostsSource
from app.blocklists.sources.torproject import (
    TorBulkExitSource, TorConsensusSource, TorExitAddressesSource,
)
from app.blocklists.sources.urlhaus import UrlhausHostnamesSource


def _default_on() -> list[BlocklistSource]:
    return [
        SpamhausDropSource(),
        SpamhausEdropSource(),
        FireholLevel1Source(),
        FireholLevel2Source(),
        IpsumSource(level=3),
        BlocklistDeSource(),
        BinaryDefenseSource(),
        FeodoSource(),
        TorBulkExitSource(),
        TorExitAddressesSource(),
        TorConsensusSource(),
        GluetunVpnSource(),
        StevenblackHostsSource(category=None),
        UrlhausHostnamesSource(),
    ]


def _default_off() -> list[BlocklistSource]:
    return [
        SpamhausDropv6Source(),
        FireholLevel3Source(),
        FireholDshieldSource(),
        FireholBruteforceblockerSource(),
        IpfireAggressiveSource(),
        AbusechSslblSource(),
        AbusechBogonsSource(),
        IpsumSource(level=5),
        StevenblackHostsSource(category="adware"),
        StevenblackHostsSource(category="fakenews"),
        StevenblackHostsSource(category="gambling"),
        StevenblackHostsSource(category="porn"),
        StevenblackHostsSource(category="social"),
    ]


def all_sources() -> list[BlocklistSource]:
    return [*_default_on(), *_default_off()]


def default_source_ids() -> set[str]:
    return {s.source_id for s in _default_on()}


def default_off_source_ids() -> set[str]:
    return {s.source_id for s in _default_off()}
