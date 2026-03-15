"""
Redis cache helpers for short-lived endpoint responses.

Provides both sync and async get/set with JSON serialization and TTL.
All operations are fail-open: if Redis is unavailable the caller simply
gets a cache miss and proceeds to compute the value from the database.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import redis
import redis.asyncio as aioredis

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy singleton connections
# ---------------------------------------------------------------------------

_async_pool: Optional[aioredis.Redis] = None
_sync_pool: Optional[redis.Redis] = None


def _get_sync_redis() -> redis.Redis:
    """Return a module-level sync Redis client (created once)."""
    global _sync_pool
    if _sync_pool is None:
        _sync_pool = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    return _sync_pool


def _get_async_redis() -> aioredis.Redis:
    """Return a module-level async Redis client (created once)."""
    global _async_pool
    if _async_pool is None:
        _async_pool = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    return _async_pool


# ---------------------------------------------------------------------------
# Async helpers (for AsyncSession endpoints)
# ---------------------------------------------------------------------------


async def cache_get_async(key: str) -> Optional[Any]:
    """Fetch a cached value by *key*, deserializing from JSON.

    Returns ``None`` on cache miss **or** on any Redis error.
    """
    try:
        r = _get_async_redis()
        raw = await r.get(key)
        if raw is not None:
            return json.loads(raw)
    except (redis.RedisError, aioredis.RedisError, OSError, json.JSONDecodeError) as exc:
        logger.warning("cache_get_async failed for %s: %s", key, exc)
    return None


async def cache_set_async(key: str, value: Any, ttl: int) -> None:
    """Serialize *value* to JSON and store under *key* with *ttl* seconds."""
    try:
        r = _get_async_redis()
        await r.set(key, json.dumps(value, default=str), ex=ttl)
    except (redis.RedisError, aioredis.RedisError, OSError, TypeError) as exc:
        logger.warning("cache_set_async failed for %s: %s", key, exc)


# ---------------------------------------------------------------------------
# Sync helpers (for Session endpoints)
# ---------------------------------------------------------------------------


def cache_get_sync(key: str) -> Optional[Any]:
    """Fetch a cached value by *key*, deserializing from JSON.

    Returns ``None`` on cache miss **or** on any Redis error.
    """
    try:
        r = _get_sync_redis()
        raw = r.get(key)
        if raw is not None:
            return json.loads(raw)
    except (redis.RedisError, OSError, json.JSONDecodeError) as exc:
        logger.warning("cache_get_sync failed for %s: %s", key, exc)
    return None


def cache_set_sync(key: str, value: Any, ttl: int) -> None:
    """Serialize *value* to JSON and store under *key* with *ttl* seconds."""
    try:
        r = _get_sync_redis()
        r.set(key, json.dumps(value, default=str), ex=ttl)
    except (redis.RedisError, OSError, TypeError) as exc:
        logger.warning("cache_set_sync failed for %s: %s", key, exc)
