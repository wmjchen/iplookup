from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after: float


class RateLimiter:
    """Sliding-window rate limiter keyed by client identifier (e.g. IP)."""

    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = Lock()

    def hit(self, key: str) -> RateLimitResult:
        if self.max_requests <= 0:
            return RateLimitResult(
                allowed=True,
                limit=self.max_requests,
                remaining=0,
                retry_after=0.0,
            )

        now = time.monotonic()
        window_start = now - self.window_seconds

        with self._lock:
            times = [t for t in self._hits.get(key, []) if t > window_start]
            if len(times) >= self.max_requests:
                retry_after = max(0.0, times[0] + self.window_seconds - now)
                self._hits[key] = times
                return RateLimitResult(
                    allowed=False,
                    limit=self.max_requests,
                    remaining=0,
                    retry_after=retry_after,
                )

            times.append(now)
            self._hits[key] = times
            remaining = self.max_requests - len(times)
            return RateLimitResult(
                allowed=True,
                limit=self.max_requests,
                remaining=remaining,
                retry_after=0.0,
            )


def path_is_rate_limited(path: str) -> bool:
    """Endpoints that hit remotes / heavy work (not /api/ip or /health)."""
    if path.startswith("/api/providers/"):
        return True
    return path in {
        "/api/lookup",
        "/api/ptr",
        "/api/whois",
        "/api/resolve",
        "/api/blocklists/refresh",
    }
