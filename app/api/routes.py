from __future__ import annotations

import asyncio
import hmac
import os
import time
import uuid

from fastapi import APIRouter, HTTPException, Query, Request, Response

from app.config import get_settings
from app.core.iputil import validate_query_ip
from app.core.orchestrator import LookupOrchestrator
from app.core.query import classify_query
from app.services.dns_resolve import resolve_domain
from app.services.ptr import reverse_dns
from app.services.whois_rdap import RdapClient

router = APIRouter()


def get_orchestrator(request: Request) -> LookupOrchestrator:
    return request.app.state.orchestrator


def get_rdap(request: Request) -> RdapClient:
    return request.app.state.rdap


def _domain_targets(dns, prefer: str) -> list[str]:
    """
    Build ordered list of IPs to fully look up for a domain.
    Always includes first A and first AAAA when present (not only one family).
    `prefer` only controls which report is primary (first in list).
    """
    a = list(dns.a or [])
    aaaa = list(dns.aaaa or [])
    first_a = a[0] if a else None
    first_aaaa = aaaa[0] if aaaa else None

    prefer_v = (prefer or "a").lower()
    if prefer_v in {"aaaa", "ipv6", "v6"}:
        ordered = [first_aaaa, first_a]
    else:
        # default: IPv4 primary, still include IPv6
        ordered = [first_a, first_aaaa]

    out: list[str] = []
    for ip in ordered:
        if ip and ip not in out:
            out.append(ip)
    return out


@router.get("/api/ip")
async def api_ip(request: Request, response: Response):
    ip = request.app.state.resolve_ip(request)
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return {"ip": ip}
    return Response(content=ip, media_type="text/plain")


@router.get("/api/resolve")
async def api_resolve(request: Request, q: str = Query(..., min_length=1)):
    try:
        kind, value = classify_query(q)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if kind == "ip":
        return {"query": value, "query_type": "ip", "a": [value], "aaaa": []}
    orch = get_orchestrator(request)
    dns = await resolve_domain(value, resolver=getattr(orch, "dns_resolver", None))
    return {
        "query": value,
        "query_type": "domain",
        "domain": dns.domain,
        "a": dns.a,
        "aaaa": dns.aaaa,
    }


_PREFER_DESC = (
    "For domains: which family is primary - a/ipv4 or aaaa/ipv6. "
    "Both are looked up when present."
)


async def _perform_lookup(
    request: Request,
    raw: str | None,
    *,
    db: str | None = None,
    prefer: str | None = "a",
):
    client_ip = request.app.state.resolve_ip(request)
    query_type = "ip"
    domain = None
    dns = None
    orch = get_orchestrator(request)
    targets: list[str] = []

    if not raw:
        targets = [client_ip]
    else:
        try:
            kind, value = classify_query(raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if kind == "ip":
            targets = [value]
        else:
            query_type = "domain"
            domain = value
            dns = await resolve_domain(
                value, resolver=getattr(orch, "dns_resolver", None)
            )
            targets = _domain_targets(dns, prefer or "a")
            if not targets:
                raise HTTPException(
                    status_code=404,
                    detail=f"no A/AAAA records for {domain}",
                )

    validated: list[str] = []
    for t in targets:
        try:
            validated.append(validate_query_ip(t))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid ip: {exc}") from exc

    # Run domain-only blocklist checks on the primary target only (the first
    # validated). Siblings still get IP-list checks.
    reports = await asyncio.gather(
        *[
            orch.lookup(
                target,
                client_ip=client_ip,
                preferred_db=db,
                domain=domain,
                dns=dns,
                query_type=query_type,
                run_domain_check=(i == 0),
            )
            for i, target in enumerate(validated)
        ]
    )

    primary = reports[0]
    if len(reports) > 1:
        # Attach sibling address-family reports (no nested related to avoid bloat)
        related = []
        for r in reports[1:]:
            copy = r.model_copy(deep=True)
            copy.related = []
            related.append(copy)
        primary.related = related
    return primary


@router.get("/api/lookup")
async def api_lookup(
    request: Request,
    ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    db: str | None = Query(default=None),
    prefer: str | None = Query(default="a", description=_PREFER_DESC),
):
    raw = q if q is not None else ip
    return await _perform_lookup(request, raw, db=db, prefer=prefer)


@router.get("/api/lookup/{query}")
async def api_lookup_path(
    request: Request,
    query: str,
    db: str | None = Query(default=None),
    prefer: str | None = Query(default="a", description=_PREFER_DESC),
):
    """Path-based alias of /api/lookup?q=query - handy for clients/extensions."""
    return await _perform_lookup(request, query, db=db, prefer=prefer)


@router.get("/api/ptr")
async def api_ptr(request: Request, ip: str | None = Query(default=None)):
    client_ip = request.app.state.resolve_ip(request)
    query = client_ip if not ip else ip
    try:
        query = validate_query_ip(query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid ip: {exc}") from exc

    rdns = await reverse_dns(query)
    return {
        "ip": query,
        "rdns": rdns,
        "timestamp": int(time.time() * 1000),
        "request_id": uuid.uuid4().hex[:16],
    }


@router.get("/api/whois")
async def api_whois(request: Request, ip: str | None = Query(default=None)):
    client_ip = request.app.state.resolve_ip(request)
    query = client_ip if not ip else ip
    try:
        query = validate_query_ip(query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid ip: {exc}") from exc

    rdap = get_rdap(request)
    info = await rdap.lookup(query)
    return info or {"ip": query, "error": "no whois data"}


@router.get("/api/providers/ip-api")
async def api_provider_ip_api(
    request: Request,
    ip: str | None = Query(default=None),
):
    """
    Server-side proxy for ip-api.com (HTTP-only free tier).

    Forwards the browser visitor IP via X-Forwarded-For / X-Real-IP so rate
    limits are attributed to the client rather than only the server.
    """
    client_ip = request.app.state.resolve_ip(request)
    target = client_ip if not ip else ip
    try:
        target = validate_query_ip(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid ip: {exc}") from exc

    provider = getattr(request.app.state, "ip_api", None)
    if provider is None:
        raise HTTPException(status_code=503, detail="ip-api proxy disabled")

    result = await provider.lookup(target, client_ip=client_ip)
    return result


@router.get("/api/providers/ipinfo-lite")
async def api_provider_ipinfo_lite(
    request: Request,
    ip: str | None = Query(default=None),
):
    """
    Server-side proxy for the IPinfo Lite API (country + ASN).
    Keeps the IPINFO_TOKEN server-side. 503 when no token is configured.
    """
    client_ip = request.app.state.resolve_ip(request)
    target = client_ip if not ip else ip
    try:
        target = validate_query_ip(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid ip: {exc}") from exc

    provider = getattr(request.app.state, "ipinfo_lite", None)
    if provider is None:
        raise HTTPException(status_code=503, detail="ipinfo-lite proxy not configured")

    return await provider.lookup(target)


@router.get("/api/blocklists")
async def api_blocklists(request: Request, response: Response):
    registry = getattr(request.app.state, "blocklist_registry", None)
    checker = getattr(request.app.state, "blocklist_checker", None)
    if registry is None or checker is None:
        raise HTTPException(status_code=503, detail="blocklists disabled")
    response.headers["Cache-Control"] = "public, max-age=60"
    from app.blocklists.sources import default_source_ids, default_off_source_ids
    return {
        "enabled": bool(getattr(checker, "enabled", True)),
        "total_entries": registry.total_entries(),
        "sources": registry.summary(),
        "default_on": sorted(default_source_ids()),
        "default_off": sorted(default_off_source_ids()),
    }


@router.get("/api/blocklists/refresh")
async def api_blocklists_refresh(
    request: Request,
    source_id: str = Query(...),
    token: str = Query(default=""),
):
    admin_token = (
        os.environ.get("BLOCKLISTS_ADMIN_TOKEN", "")
        or getattr(get_settings(), "blocklists_admin_token", "")
    )
    if not admin_token or not hmac.compare_digest(admin_token, token):
        raise HTTPException(status_code=404)
    registry = getattr(request.app.state, "blocklist_registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="blocklists disabled")
    result = await registry.refresh_source(source_id)
    return {
        "source_id": result.source_id,
        "refreshed": result.refreshed,
        "entries": result.entries,
        "last_refreshed": result.last_refreshed,
        "last_error": result.last_error,
    }


@router.get("/health")
async def health(request: Request):
    registry = getattr(request.app.state, "blocklist_registry", None)
    checker = getattr(request.app.state, "blocklist_checker", None)
    blocklists_status: dict = {"enabled": bool(checker)}
    if registry is not None and checker is not None:
        import time as _time
        now = _time.time()
        ages = []
        for s in registry.enabled_sources():
            _, refreshed, _ = registry.snapshot(s.source_id)
            if refreshed is not None:
                ages.append(now - refreshed)
        blocklists_status.update({
            "total_entries": registry.total_entries(),
            "sources": len(registry.enabled_sources()),
            "last_refreshed_max_age_seconds": int(max(ages)) if ages else None,
        })
    return {
        "status": "ok",
        "maxmind": bool(getattr(request.app.state, "maxmind_loaded", False)),
        "ip_index": bool(getattr(request.app.state, "ip_index_loaded", False)),
        "hosting_asns": int(getattr(request.app.state, "hosting_asn_count", 0)),
        "browser_sources": True,
        "ip_api_proxy": getattr(request.app.state, "ip_api", None) is not None,
        "blocklists": blocklists_status,
        "ipfire": bool(getattr(request.app.state, "ipfire_loaded", False)),
        "ip2location": bool(getattr(request.app.state, "ip2location_loaded", False)),
        "ipinfo_lite_proxy": getattr(request.app.state, "ipinfo_lite", None) is not None,
        "version": "0.1.0",
    }
