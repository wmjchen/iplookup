from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Sequence

from app.core.cache import TTLCache
from app.core.iputil import classify_address, ip_version, is_public_ip, parse_ip
from app.core.models import (
    Classification,
    LookupReport,
    MapInfo,
    NetworkInfo,
    ProviderResult,
    WhoisInfo,
    BlocklistReport,
)
from app.core.native_broadcast import classify_native_broadcast
from app.core.risk import score_risk
from app.core.usage import classify_usage, merge_usage_signals
from app.providers.base import Provider
from app.services.ptr import reverse_dns
from app.services.whois_rdap import RdapClient


def pick_primary(
    sources: Sequence[ProviderResult],
    preferred_db: str | None = None,
) -> ProviderResult | None:
    healthy = [s for s in sources if s.error is None]
    if not healthy:
        return None
    if preferred_db:
        for s in healthy:
            if s.provider_id == preferred_db:
                return s
    for s in healthy:
        if s.provider_id == "maxmind":
            return s
    for s in healthy:
        if s.latitude is not None and s.longitude is not None:
            return s
    return healthy[0]


class LookupOrchestrator:
    def __init__(
        self,
        providers: list[Provider],
        rdap: RdapClient | None = None,
        cache: TTLCache[LookupReport] | None = None,
        provider_timeout: float = 1.2,
        ptr_resolver: Any | None = None,
        dns_resolver: Any | None = None,
        blocklist_checker: Any | None = None,
    ) -> None:
        self.providers = providers
        self.rdap = rdap or RdapClient()
        self.cache = cache
        self.provider_timeout = provider_timeout
        self.ptr_resolver = ptr_resolver
        self.dns_resolver = dns_resolver
        self.blocklist_checker = blocklist_checker

    async def _run_provider(self, provider: Provider, ip: str) -> ProviderResult:
        try:
            return await asyncio.wait_for(
                provider.lookup(ip), timeout=self.provider_timeout
            )
        except TimeoutError:
            return ProviderResult(
                provider_id=getattr(provider, "provider_id", "unknown"),
                ip=ip,
                error="timeout",
            )
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider_id=getattr(provider, "provider_id", "unknown"),
                ip=ip,
                error=str(exc),
            )

    async def lookup(
        self,
        ip: str,
        *,
        client_ip: str | None = None,
        preferred_db: str | None = None,
        skip_cache: bool = False,
        domain: str | None = None,
        dns: Any | None = None,
        query_type: str = "ip",
        run_domain_check: bool = True,
    ) -> LookupReport:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex[:16]
        cache_key = f"{domain or ''}|{ip}|{preferred_db or ''}"

        if self.cache is not None and not skip_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                report = cached.model_copy(deep=True)
                report.cached = True
                report.request_id = request_id
                report.client_ip = client_ip
                report.took_ms = int((time.perf_counter() - started) * 1000)
                return report

        parsed = parse_ip(ip)
        version = ip_version(parsed)
        address_class = classify_address(parsed)
        private = not is_public_ip(parsed)

        sources: list[ProviderResult] = []
        whois: WhoisInfo | None = None
        rdns: str | None = None
        blocklist_report: BlocklistReport | None = None

        if private:
            sources = []
        else:
            provider_tasks = [self._run_provider(p, ip) for p in self.providers]
            ptr_task = reverse_dns(ip, resolver=self.ptr_resolver)
            whois_task = self.rdap.lookup(ip)

            domain_for_check = domain if run_domain_check else None
            blocklist_task = (
                self.blocklist_checker.check(ip=ip, domain=domain_for_check)
                if self.blocklist_checker is not None else None
            )

            gather_args = [*provider_tasks, ptr_task, whois_task]
            if blocklist_task is not None:
                gather_args.append(blocklist_task)
            results = await asyncio.gather(*gather_args, return_exceptions=True)

            n = len(provider_tasks)
            for item in results[:n]:
                if isinstance(item, ProviderResult):
                    sources.append(item)
                elif isinstance(item, Exception):
                    sources.append(
                        ProviderResult(
                            provider_id="unknown", ip=ip, error=str(item)
                        )
                    )
            ptr_result = results[n]
            whois_result = results[n + 1]
            if isinstance(ptr_result, str) or ptr_result is None:
                rdns = ptr_result
            whois = whois_result if isinstance(whois_result, WhoisInfo) else None
            if blocklist_task is not None:
                blocklist_result = results[n + 2]
                blocklist_report = (
                    blocklist_result
                    if isinstance(blocklist_result, BlocklistReport)
                    else None
                )

        primary = pick_primary(sources, preferred_db=preferred_db)
        is_hosting, is_proxy, is_mobile, signals = merge_usage_signals(sources)

        usage_cc = primary.country_code if primary else None
        reg_cc = whois.country if whois else None
        # whois country may be full name; only use 2-letter codes for native check
        if reg_cc and len(reg_cc.strip()) != 2:
            reg_cc = None
        ip_type = classify_native_broadcast(
            usage_country_code=usage_cc,
            registration_country_code=reg_cc,
        )

        usage = classify_usage(
            is_hosting=is_hosting,
            is_mobile=is_mobile,
            is_private=private,
            signals=signals,
            sources=sources,
        )

        # Promote blocklist hits to proxy_signals (mutates local list)
        if blocklist_report:
            if any(h.category == "vpn_endpoint" for h in blocklist_report.hits) and not is_proxy:
                signals = [*signals, "vpn_endpoint"]
                is_proxy = True
            if any(h.category == "tor_exit" for h in blocklist_report.hits):
                if "tor_exit" not in signals:
                    signals = [*signals, "tor_exit"]
            if any(h.category == "tor_relay" for h in blocklist_report.hits):
                if "tor_relay" not in signals:
                    signals = [*signals, "tor_relay"]

        risk = score_risk(
            sources=sources,
            is_hosting=is_hosting,
            is_proxy=is_proxy,
            is_mobile=bool(is_mobile),
            is_private=private,
            proxy_signals=signals,
            blocklist_hits=blocklist_report.hits if blocklist_report else None,
        )

        network = NetworkInfo(
            asn=primary.asn if primary else None,
            as_name=primary.as_name if primary else None,
            isp=primary.isp if primary else None,
            org=primary.org if primary else None,
            rdns=rdns,
        )

        map_info = None
        if primary and primary.latitude is not None and primary.longitude is not None:
            map_info = MapInfo(lat=primary.latitude, lon=primary.longitude)

        report = LookupReport(
            query=str(parsed),
            query_type=query_type if query_type in {"ip", "domain"} else "ip",  # type: ignore[arg-type]
            domain=domain,
            dns=dns,
            client_ip=client_ip,
            ip_version=version,
            sources=sources,
            primary=primary,
            network=network,
            classification=Classification(
                ip_type=ip_type,
                usage=usage,  # type: ignore[arg-type]
                proxy_signals=signals,
                address_class=address_class,
            ),
            risk_score=risk,
            whois=whois,
            map=map_info,
            blocklists=blocklist_report,
            request_id=request_id,
            cached=False,
            took_ms=int((time.perf_counter() - started) * 1000),
        )

        if self.cache is not None and not private:
            self.cache.set(cache_key, report)

        return report
