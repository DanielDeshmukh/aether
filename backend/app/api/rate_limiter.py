import time
import logging
from collections import defaultdict
from typing import Dict, List

from fastapi import HTTPException, Request, status

logger = logging.getLogger("aether.rate_limiter")


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, List[float]] = defaultdict(list)

    def _evict(self, key: str, window_seconds: float) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        self._hits[key] = [t for t in self._hits[key] if t > cutoff]

    def check(self, key: str, max_hits: int, window_seconds: float) -> None:
        self._evict(key, window_seconds)
        if len(self._hits[key]) >= max_hits:
            retry_after = int(self._hits[key][0] + window_seconds - time.monotonic()) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                headers={"Retry-After": str(max(1, retry_after))},
            )
        self._hits[key].append(time.monotonic())


_limiter = InMemoryRateLimiter()


async def rate_limit_magic_link(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(
        key=f"magic-link:{client_ip}",
        max_hits=5,
        window_seconds=3600,
    )


async def rate_limit_refresh(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(
        key=f"refresh:{client_ip}",
        max_hits=20,
        window_seconds=3600,
    )


async def rate_limit_scan_creation(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(
        key=f"scan-create:{client_ip}",
        max_hits=10,
        window_seconds=3600,
    )


async def rate_limit_report_download(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(
        key=f"report-dl:{client_ip}",
        max_hits=30,
        window_seconds=3600,
    )


async def rate_limit_report_email(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(
        key=f"report-email:{client_ip}",
        max_hits=5,
        window_seconds=3600,
    )
