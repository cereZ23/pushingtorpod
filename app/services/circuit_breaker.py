"""Per-target circuit breaker — auto back-off when a host starts falling over.

Tracks consecutive failures per host in Redis. After ``threshold`` failures the
host's circuit is "open" and active probes skip it for ``ttl`` seconds, so an
aggressive scan can't keep hammering a target that's already returning errors or
timing out. A success resets the counter.

Fail-open: on any Redis error the circuit reads as *closed* (probing continues),
so the breaker can never itself block scanning.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.config import settings
from app.core.cache import _get_sync_redis

logger = logging.getLogger(__name__)

_KEY = "easm:cb:{}"


def _key(host: str) -> str:
    return _KEY.format((host or "").strip().lower())


def record_failure(host: str, ttl: Optional[int] = None) -> int:
    """Record a probe failure for ``host``; returns the new failure count."""
    if not host:
        return 0
    try:
        r = _get_sync_redis()
        count = r.incr(_key(host))
        r.expire(_key(host), ttl or settings.circuit_breaker_ttl)
        if count == settings.circuit_breaker_threshold:
            logger.warning("[circuit-breaker] OPEN for %s after %d failures", host, count)
        return int(count)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("circuit-breaker record_failure failed: %s", exc)
        return 0


def record_success(host: str) -> None:
    """Reset the breaker for ``host`` (it responded)."""
    if not host:
        return
    try:
        _get_sync_redis().delete(_key(host))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("circuit-breaker record_success failed: %s", exc)


def is_open(host: str, threshold: Optional[int] = None) -> bool:
    """True if ``host``'s circuit is open (too many recent failures) -> skip it.

    Fail-open: Redis errors read as closed (not open) so probing continues.
    """
    if not host:
        return False
    try:
        count = int(_get_sync_redis().get(_key(host)) or 0)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("circuit-breaker is_open check failed (closed): %s", exc)
        return False
    return count >= (threshold or settings.circuit_breaker_threshold)
