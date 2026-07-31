# iplookup

Look up an IP or domain and get geolocation, ASN/hosting signals, reverse DNS, RDAP, and blocklist hits from several local databases and free APIs.

## Setup

```bash
uv sync
cp .env.example .env   # optional — fill in tokens you have
uv run python scripts/fetch_databases.py
uv run iplookup
```

Open http://127.0.0.1:8000/ (API docs at `/docs`).

`scripts/fetch_databases.py` fills `data/` at build or setup time:

| Database | Env var |
|----------|---------|
| ip-index, IPFire Location | none (always fetched) |
| MaxMind GeoLite2 City + ASN | `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` |
| IP2Location LITE DB11 | `IP2LOCATION_DOWNLOAD_TOKEN` |
| IPinfo Lite (live API, not a file) | `IPINFO_TOKEN` |

Missing token → that source is skipped; the rest still work. Blocklists refresh themselves while the app runs.

## Deploy (Coolify / Nixpacks)

Repo includes `nixpacks.toml`: install deps, run `fetch_databases.py`, start uvicorn on `$PORT`.

Set these as **build-time** variables so the fetch step can reach paid/free-with-account DBs:

- `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` (from your MaxMind account portal)
- `IP2LOCATION_DOWNLOAD_TOKEN`

Runtime:

- `IPINFO_TOKEN` (optional)
- `BLOCKLISTS_ADMIN_TOKEN` (optional)

Keep a persistent volume on `data/` only if you want caches to survive redeploys; GeoIP files are re-pulled every build.

## Tests

```bash
uv run pytest -q
```

## Attribution

- GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com)
- IP geolocation data by [IPFire Location](https://www.ipfire.org/location/) (CC BY-SA 4.0)
- [IP2Location LITE](https://lite.ip2location.com) for IP geolocation
- `app/vendor/pylibloc.py` from [gereoffy/pylibloc](https://github.com/gereoffy/pylibloc) (LGPL-2.1)
- Map tiles © [OpenStreetMap](https://www.openstreetmap.org/copyright) contributors
