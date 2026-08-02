from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.blocklists.checker import BlocklistChecker
from app.blocklists.registry import BlocklistRegistry
from app.config import get_settings
from app.core.cache import TTLCache
from app.core.client_ip import resolve_client_ip
from app.core.models import LookupReport
from app.core.orchestrator import LookupOrchestrator
from app.core.rate_limit import RateLimiter, path_is_rate_limited
from app.providers.hosting_asn import HostingAsnIndex
from app.providers.ip2location import Ip2LocationProvider
from app.providers.ip_api import IpApiProvider
from app.providers.ip_index import IpIndexProvider
from app.providers.ipfire import IpfireProvider
from app.providers.ipinfo_lite import IpinfoLiteProvider
from app.providers.ipwhois import IpWhoisProvider
from app.providers.maxmind import MaxMindProvider
from app.services.whois_rdap import RdapClient

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    hosting = HostingAsnIndex(path=settings.resolved_hosting_asn_file())
    providers = []
    maxmind = None

    if settings.enable_maxmind:
        maxmind = MaxMindProvider(
            city_db=settings.resolved_city_db(),
            asn_db=settings.resolved_asn_db(),
            hosting_check=hosting if settings.enable_hosting_asn else None,
        )
        providers.append(maxmind)

    ip_index = None
    if settings.enable_ip_index:
        ip_index = IpIndexProvider(db_path=settings.resolved_ip_index_db())
        if ip_index.available:
            providers.append(ip_index)

    ipfire = None
    if settings.enable_ipfire:
        ipfire = IpfireProvider(db_path=settings.resolved_ipfire_db())
        providers.append(ipfire)

    ip2location = None
    if settings.enable_ip2location:
        ip2location = Ip2LocationProvider(db_path=settings.resolved_ip2location_db())
        providers.append(ip2location)

    # ip-api is only used via dedicated proxy endpoint (not orchestrator fan-out)
    ip_api = None
    if settings.enable_ip_api_proxy:
        ip_api = IpApiProvider(timeout=settings.provider_timeout_ms / 1000)

    ipinfo_lite = None
    if settings.enable_ipinfo_lite and settings.ipinfo_token:
        ipinfo_lite = IpinfoLiteProvider(
            token=settings.ipinfo_token,
            timeout=settings.provider_timeout_ms / 1000,
        )

    ipwhois = None
    if settings.enable_ipwhois:
        ipwhois = IpWhoisProvider(timeout=settings.provider_timeout_ms / 1000)
        providers.append(ipwhois)

    blocklist_checker = None
    blocklist_registry: BlocklistRegistry | None = None
    if settings.enable_blocklists:
        blocklist_registry = BlocklistRegistry(
            data_dir=settings.resolved_blocklists_dir(),
            extra_source_ids=settings.blocklists_extra_sources_list() or None,
            user_agent=settings.blocklists_user_agent,
            offline_mode=settings.blocklists_offline_mode,
            fetch_timeout=settings.blocklists_refresh_timeout_ms / 1000,
        )
        await blocklist_registry.load_disk_cache()  # always - non-network
        if settings.blocklists_refresh_on_startup and not settings.blocklists_offline_mode:
            await blocklist_registry.load_all()  # also fetch fresh
        await blocklist_registry.start_refresh_tasks()
        blocklist_checker = BlocklistChecker(registry=blocklist_registry, enabled=True)

    rdap = RdapClient(timeout=settings.provider_timeout_ms / 1000)
    cache: TTLCache[LookupReport] = TTLCache(ttl_seconds=settings.cache_ttl_seconds)
    orch = LookupOrchestrator(
        providers=providers,
        rdap=rdap,
        cache=cache,
        provider_timeout=settings.provider_timeout_ms / 1000,
        blocklist_checker=blocklist_checker,
    )

    app.state.settings = settings
    app.state.orchestrator = orch
    app.state.rdap = rdap
    app.state.maxmind = maxmind
    app.state.ip_index = ip_index
    app.state.maxmind_loaded = bool(maxmind and maxmind.available)
    app.state.ip_index_loaded = bool(ip_index and ip_index.available)
    app.state.ipfire = ipfire
    app.state.ip2location = ip2location
    app.state.ipinfo_lite = ipinfo_lite
    app.state.ipfire_loaded = bool(ipfire and ipfire.available)
    app.state.ip2location_loaded = bool(ip2location and ip2location.available)
    app.state.hosting_asn_count = len(hosting)
    app.state.ip_api = ip_api
    app.state.ipwhois = ipwhois
    app.state.blocklist_registry = blocklist_registry
    app.state.blocklist_checker = blocklist_checker
    app.state.rate_limiter = RateLimiter(
        max_requests=settings.rate_limit_per_minute,
        window_seconds=60.0,
    )

    def _resolve(request: Request) -> str:
        headers = {k: v for k, v in request.headers.items()}
        peer = request.client.host if request.client else None
        return resolve_client_ip(
            headers=headers,
            peer=peer,
            trust_proxy=settings.trust_proxy,
        )

    app.state.resolve_ip = _resolve

    try:
        yield
    finally:
        if blocklist_registry is not None:
            await blocklist_registry.stop_refresh_tasks()
        if maxmind is not None:
            maxmind.close()
        if ip_index is not None:
            ip_index.close()
        if ipfire is not None:
            ipfire.close()
        if ip2location is not None:
            ip2location.close()
        if ip_api is not None:
            await ip_api.aclose()
        if ipinfo_lite is not None:
            await ipinfo_lite.aclose()
        if ipwhois is not None:
            await ipwhois.aclose()
        await rdap.aclose()


app = FastAPI(title="iplookup", version="0.1.0", lifespan=lifespan)
app.include_router(router)

if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not path_is_rate_limited(request.url.path):
        return await call_next(request)

    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return await call_next(request)

    resolve = getattr(request.app.state, "resolve_ip", None)
    if resolve is not None:
        client_key = resolve(request)
    else:
        client_key = request.client.host if request.client else "0.0.0.0"

    result = limiter.hit(client_key)
    if not result.allowed:
        retry_after = max(1, int(result.retry_after + 0.999))
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded"},
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(result.limit)
    response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    return response


@app.get("/")
async def index():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "iplookup API", "docs": "/docs"}


@app.get("/{query}")
async def lookup_page(query: str):
    """
    Path-based lookup URLs (e.g. /8.8.8.8, /google.com) for Firefox extension /
    omnibox use. Serves the SPA; the client reads location.pathname and
    auto-looks-up. Registered last so /docs, /api/*, /static/*, /health win.
    """
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "iplookup API", "docs": "/docs"}


def run() -> None:
    """Console entrypoint for `uv run iplookup` / project.scripts."""
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
