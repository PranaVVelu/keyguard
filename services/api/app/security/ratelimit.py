"""Fixed-window rate limiting (T12, D-009, D-013).

Two stores with the same interface:
  * RateLimiter (memory, default): per process, so N workers allow up to N times the configured rate.
  * DatabaseRateLimiter: counters in the shared database, so every worker and instance sees the same count.
    One atomic upsert per hit; keys are stored as SHA-256 hashes, never raw client addresses.

client_address() takes the direct peer address, or, only when that peer is a configured trusted proxy,
the right-most untrusted entry of X-Forwarded-For.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
import hashlib
import ipaddress
from dataclasses import dataclass

from sqlalchemy import Engine
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
    auth: Limit | None = Limit(30, 60)  # WebAuthn options/verify endpoints, per client address (D-012)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RateLimits:
        env = os.environ if env is None else env

        def parse(name: str, default: Limit | None) -> Limit | None:
            raw = env.get(name)
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
            auth=parse("KEYGUARD_RATE_AUTH", d.auth),
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


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted_proxies(raw: str | None) -> tuple[Network, ...]:
    """Comma-separated IPs or CIDRs (e.g. "10.0.0.0/8, 127.0.0.1"). Raises ValueError on a bad entry."""
    if not raw:
        return ()
    return tuple(ipaddress.ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip())


def _trusted(addr: str, proxies: tuple[Network, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in proxies)


def resolve_client(peer: str | None, forwarded_for: str | None, proxies: tuple[Network, ...]) -> str:
    """The address to rate-limit on.

    X-Forwarded-For is only believed when the direct peer is a trusted proxy. Then the list is read from the
    right (nearest hop first), skipping trusted proxies; the first untrusted hop is the client. Entries left
    of it were supplied by the client itself and are ignored, so a client can't pick its own key.
    """
    peer = peer or "unknown"
    if not proxies or not forwarded_for or not _trusted(peer, proxies):
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed chain: fall back to the proxy rather than trust garbage
        if not _trusted(hop, proxies):
            return hop
    return hops[0] if hops else peer


def client_address(request: Request) -> str:
    proxies = getattr(request.app.state, "trusted_proxies", ())
    return resolve_client(
        request.client.host if request.client else None, request.headers.get("x-forwarded-for"), proxies
    )


class DatabaseRateLimiter:
    """Same interface as RateLimiter; counters live in the `rate_limit_counters` table."""

    def __init__(self, engine: Engine, clock: Callable[[], int]) -> None:
        self._engine, self._clock = engine, clock

    def hit(self, bucket: str, key: str, limit: Limit | None) -> int | None:
        if limit is None:
            return None
        from app.models.tables import rate_limit_counters as t

        now = self._clock()
        window_start = now - (now % limit.window_seconds)
        digest = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()
        if self._engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        stmt = insert(t).values(bucket=bucket, key_hash=digest, window_start=window_start, count=1)
        stmt = stmt.on_conflict_do_update(
            index_elements=[t.c.bucket, t.c.key_hash, t.c.window_start], set_={"count": t.c.count + 1}
        ).returning(t.c.count)
        with self._engine.begin() as conn:
            count = conn.execute(stmt).scalar_one()
        if count > limit.requests:
            return max(1, window_start + limit.window_seconds - now)
        return None
