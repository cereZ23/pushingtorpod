"""
Rate limiter instance shared across the application.

Separated from main.py to avoid circular imports when used in routers.

Architecture:
    - SlowAPI Limiter with Redis-backed storage and smart key resolution
    - Global default: 100 req/min (applied to endpoints without explicit @limiter.limit())
    - Mutation middleware: 30 req/min for POST/PUT/PATCH/DELETE
    - Per-endpoint overrides (e.g. "5/minute" on /login) take precedence
    - Key function: user_id from JWT when authenticated, client IP otherwise

OWASP: A04:2021 - Insecure Design (rate limiting prevents brute force / DoS)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# Default rate limit strings
GLOBAL_DEFAULT_LIMIT = "100/minute"
MUTATION_DEFAULT_LIMIT = "30/minute"

# HTTP methods considered mutations
MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Paths excluded from rate limiting (health, docs, OpenAPI schema)
RATE_LIMIT_EXEMPT_PATHS = frozenset(
    {
        "/health",
        "/health/metrics",
        "/ready",
        "/metrics",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
    }
)


def _get_rate_limit_key(request: Request) -> str:
    """
    Smart rate-limit key function.

    Resolution order:
        1. If a valid JWT is present, key by user_id (``user:<id>``)
        2. Otherwise, fall back to client IP address

    This ensures authenticated users get per-user buckets while
    unauthenticated traffic is limited by IP.
    """
    # Try to extract user_id from Authorization header (JWT)
    auth_header: Optional[str] = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        try:
            import jwt as pyjwt

            # Decode without verification -- we only need the subject claim
            # for rate-limit keying.  Full verification happens later in the
            # dependency chain.  Using ``options`` to skip expiry/signature
            # checks keeps this function fast and avoids key-loading here.
            payload = pyjwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                },
                algorithms=["RS256", "HS256"],
            )
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except Exception:
            # Token is malformed -- fall through to IP-based limiting
            pass

    return get_remote_address(request)


def _build_redis_uri() -> Optional[str]:
    """
    Build the Redis URI for rate-limit storage.

    Returns ``None`` when Redis is unreachable or not configured,
    which makes slowapi fall back to in-memory storage (acceptable
    for single-process dev environments).
    """
    try:
        from app.config import settings

        return settings.redis_url
    except Exception:
        logger.warning("Could not load Redis URL from settings; rate limiter will use in-memory storage")
        return None


# ---------------------------------------------------------------------------
# Limiter singleton
# ---------------------------------------------------------------------------
# ``default_limits`` applies to every endpoint that does NOT have an
# explicit ``@limiter.limit()`` decorator.  Explicit per-endpoint limits
# always take precedence.
limiter = Limiter(
    key_func=_get_rate_limit_key,
    default_limits=[GLOBAL_DEFAULT_LIMIT],
    storage_uri=_build_redis_uri(),
    strategy="fixed-window",
)
