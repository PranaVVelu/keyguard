"""Fixed-window rate limiting (T12, D-009).

In-process and in-memory: each API process keeps its own counters, so N workers allow up to N times the
configured rate. That is acceptable for the local-first demo; a hosted multi-worker deployment would need a
shared store (documented limitation, D-009).
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from dataclasses import dataclass

from starlette.requests import Request


@dataclass(frozen=True)
class Limit:
    requests: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimits:
    """All limits are per fixed window. `None` disables that limit (only used by tooling, never by default)."""

    client: Limit | None = Limit(600, 60)  # every /api request, per client address
    lab_create: Limit | None = Limit(20, 60)  # POST /api/labs, per client address
    lab: Limit | None = Limit(120, 60)  # authorized requests, per lab

    @classmethod
    def from_env(cls) -> RateLimits:
        def parse(name: str, default: Limit | None) -> Limit | None:
            raw = os.environ.get(name)
            if raw is None:
                return default
            if raw.strip().lower() == "off":
                return None
            n, _, w = raw.partition("/")
            return Limit(int(n), int(w or 60))

        d = cls()
        return cls(
            client=parse("KEYGUARD_RATE_CLIENT", d.client),
            lab_create=parse("KEYGUARD_RATE_LAB_CREATE", d.lab_create),
            lab=parse("KEYGUARD_RATE_LAB", d.lab),
        )


class RateLimiter:
    """Counts hits per (bucket, key) in the current window. Thread-safe; memory is bounded by pruning old windows."""

    MAX_TRACKED_KEYS = 50_000

    def __init__(self, clock: Callable[[], int]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str], tuple[int, int]] = {}  # (bucket, key) -> (window_start, count)

    def hit(self, bucket: str, key: str, limit: Limit | None) -> int | None:
        """Record one request. Returns None if allowed, else the seconds until the window resets (Retry-After)."""
        if limit is None:
            return None
        now = self._clock()
        window_start = now - (now % limit.window_seconds)
        with self._lock:
            if len(self._counts) >= self.MAX_TRACKED_KEYS:
                self._prune(now)
            start, count = self._counts.get((bucket, key), (window_start, 0))
            if start != window_start:
                start, count = window_start, 0
            if count >= limit.requests:
                return max(1, start + limit.window_seconds - now)
            self._counts[(bucket, key)] = (start, count + 1)
            return None

    def _prune(self, now: int) -> None:
        # Drop entries whose window began more than an hour ago (longer than any configured window).
        stale = [k for k, (start, _) in self._counts.items() if start < now - 3600]
        for k in stale:
            del self._counts[k]
        if len(self._counts) >= self.MAX_TRACKED_KEYS:
            # Still full (a flood from very many addresses): bounded memory wins over exact counting, so forget
            # current counts. This briefly loosens limits; it never blocks legitimate traffic or exhausts memory.
            self._counts.clear()


def client_address(request: Request) -> str:
    # Direct peer address. Behind a reverse proxy this is the proxy; a hosted deployment must configure
    # trusted forwarding headers before relying on per-client limits (D-009).
    return request.client.host if request.client else "unknown"
