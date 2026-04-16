"""
Unit tests for app/core/rate_limiter.py

Covers:
- RateLimiter.__init__ (injected redis client)
- _get_key
- check_rate_limit: allowed path, denied path, Redis error -> fail open
- reset_limit: success and error
- get_usage: returns count, Redis error returns 0
- RateLimitMiddleware: health check bypass, disabled rate limiting,
  global limit exceeded, IP limit exceeded, happy path
- get_rate_limiter: returns instance
- rate_limit decorator: request extraction, IP scope, no request fallthrough
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis

from app.core import rate_limiter as rl_mod
from app.core.rate_limiter import (
    RateLimiter,
    RateLimitMiddleware,
    get_rate_limiter,
    rate_limit,
)


class _FakePipeline:
    def __init__(self, *, zcard_result=0, raise_on_execute=False):
        self.zcard_result = zcard_result
        self.raise_on_execute = raise_on_execute

    def zremrangebyscore(self, *args, **kw):
        return self

    def zcard(self, *args, **kw):
        return self

    def zadd(self, *args, **kw):
        return self

    def expire(self, *args, **kw):
        return self

    def execute(self):
        if self.raise_on_execute:
            raise redis.RedisError("redis down")
        # Returns list matching operations; index 1 is zcard count
        return [None, self.zcard_result, None, None]


def _fake_redis(zcard_result=0, raise_on_execute=False, raise_on_delete=False, raise_on_zcount=False, zcount_return=0):
    r = MagicMock()

    pipe = _FakePipeline(zcard_result=zcard_result, raise_on_execute=raise_on_execute)
    r.pipeline = MagicMock(return_value=pipe)

    if raise_on_delete:
        r.delete = MagicMock(side_effect=redis.RedisError("x"))
    else:
        r.delete = MagicMock(return_value=1)

    if raise_on_zcount:
        r.zcount = MagicMock(side_effect=redis.RedisError("x"))
    else:
        r.zcount = MagicMock(return_value=zcount_return)

    return r


class TestRateLimiter:
    def test_init_with_client(self):
        fake = MagicMock()
        rl = RateLimiter(redis_client=fake)
        assert rl.redis is fake
        assert rl.default_limit == 100
        assert rl.default_window == 60

    def test_get_key_formatting(self):
        rl = RateLimiter(redis_client=MagicMock())
        assert rl._get_key("user1", "user") == "ratelimit:user:user1"

    def test_check_rate_limit_allowed(self):
        rl = RateLimiter(redis_client=_fake_redis(zcard_result=5))
        allowed, remaining, reset_time = rl.check_rate_limit("user1", limit=10, window=60, scope="user")
        assert allowed is True
        assert remaining == 4  # 10 - 5 - 1

    def test_check_rate_limit_exceeded(self):
        rl = RateLimiter(redis_client=_fake_redis(zcard_result=15))
        allowed, remaining, _ = rl.check_rate_limit("u1", limit=10, window=60)
        assert allowed is False
        assert remaining == 0

    def test_check_rate_limit_at_limit(self):
        rl = RateLimiter(redis_client=_fake_redis(zcard_result=10))
        allowed, remaining, _ = rl.check_rate_limit("u1", limit=10, window=60)
        assert allowed is False

    def test_check_rate_limit_redis_error_fails_open(self):
        rl = RateLimiter(redis_client=_fake_redis(raise_on_execute=True))
        allowed, remaining, _ = rl.check_rate_limit("u1", limit=10, window=60)
        assert allowed is True

    def test_check_rate_limit_uses_defaults(self):
        rl = RateLimiter(
            redis_client=_fake_redis(zcard_result=0),
            default_limit=5,
            default_window=30,
        )
        allowed, remaining, _ = rl.check_rate_limit("u1")
        assert allowed is True
        assert remaining == 4

    def test_reset_limit(self):
        fake = _fake_redis()
        rl = RateLimiter(redis_client=fake)
        rl.reset_limit("u1", scope="user")
        fake.delete.assert_called_once()

    def test_reset_limit_redis_error(self):
        fake = _fake_redis(raise_on_delete=True)
        rl = RateLimiter(redis_client=fake)
        # Should not raise
        rl.reset_limit("u1")

    def test_get_usage(self):
        fake = _fake_redis(zcount_return=7)
        rl = RateLimiter(redis_client=fake)
        assert rl.get_usage("u1") == 7

    def test_get_usage_redis_error(self):
        fake = _fake_redis(raise_on_zcount=True)
        rl = RateLimiter(redis_client=fake)
        assert rl.get_usage("u1") == 0


class TestGetRateLimiter:
    def test_returns_singleton(self):
        rl = get_rate_limiter()
        assert isinstance(rl, RateLimiter)


class _FakeSettings:
    def __init__(self, rate_limit_enabled=True):
        self.rate_limit_enabled = rate_limit_enabled


def _make_request(path="/api/v1/x", host="1.2.3.4", method="GET"):
    req = MagicMock()
    req.url = MagicMock()
    req.url.path = path
    req.method = method
    req.client = MagicMock()
    req.client.host = host
    req.headers = {}
    return req


class TestRateLimitMiddleware:
    @pytest.mark.asyncio
    async def test_health_check_bypassed(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        req = _make_request(path="/health")
        call_next = AsyncMock(return_value="OK")
        with patch.object(rl_mod, "settings", _FakeSettings()):
            result = await middleware.dispatch(req, call_next)
        assert result == "OK"
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_ready_check_bypassed(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        req = _make_request(path="/ready")
        call_next = AsyncMock(return_value="OK")
        with patch.object(rl_mod, "settings", _FakeSettings()):
            result = await middleware.dispatch(req, call_next)
        assert result == "OK"

    @pytest.mark.asyncio
    async def test_disabled_bypasses_limiter(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        req = _make_request()
        call_next = AsyncMock(return_value="OK")
        with patch.object(rl_mod, "settings", _FakeSettings(rate_limit_enabled=False)):
            result = await middleware.dispatch(req, call_next)
        assert result == "OK"

    @pytest.mark.asyncio
    async def test_global_limit_exceeded(self):
        fake_rl = MagicMock()
        fake_rl.check_rate_limit.return_value = (False, 0, 1234567890)
        middleware = RateLimitMiddleware(app=MagicMock())
        middleware.rate_limiter = fake_rl
        req = _make_request()
        call_next = AsyncMock()
        with patch.object(rl_mod, "settings", _FakeSettings()):
            response = await middleware.dispatch(req, call_next)
        assert response.status_code == 429
        assert b"Global rate limit exceeded" in response.body
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_ip_limit_exceeded(self):
        # Global OK, IP denied
        fake_rl = MagicMock()
        fake_rl.check_rate_limit.side_effect = [
            (True, 100, 1234567890),  # global
            (False, 0, 1234567890),  # ip
        ]
        middleware = RateLimitMiddleware(app=MagicMock())
        middleware.rate_limiter = fake_rl
        req = _make_request()
        call_next = AsyncMock()
        with patch.object(rl_mod, "settings", _FakeSettings()):
            response = await middleware.dispatch(req, call_next)
        assert response.status_code == 429
        assert b"IP rate limit exceeded" in response.body

    @pytest.mark.asyncio
    async def test_happy_path_adds_headers(self):
        fake_rl = MagicMock()
        fake_rl.check_rate_limit.side_effect = [
            (True, 50, 1234567890),
            (True, 40, 1234567890),
        ]
        middleware = RateLimitMiddleware(app=MagicMock())
        middleware.rate_limiter = fake_rl

        # Make a response object that supports .headers dict
        real_response = MagicMock()
        real_response.headers = {}

        req = _make_request()
        call_next = AsyncMock(return_value=real_response)
        with patch.object(rl_mod, "settings", _FakeSettings()):
            result = await middleware.dispatch(req, call_next)
        assert result is real_response
        assert result.headers["X-RateLimit-Limit"] == str(middleware.ip_limit)
        assert result.headers["X-RateLimit-Remaining"] == "40"


class TestRateLimitDecorator:
    @pytest.mark.asyncio
    async def test_decorator_no_request_passes_through(self):
        @rate_limit(limit=10, window=60)
        async def handler(x):
            return x * 2

        result = await handler(x=5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_decorator_ip_scope_allowed(self):
        req = _make_request(host="9.9.9.9")
        with patch.object(rl_mod._rate_limiter, "check_rate_limit") as mock_check:
            mock_check.return_value = (True, 10, 99999)

            @rate_limit(limit=10, window=60, scope="ip")
            async def handler(request):
                return "ok"

            result = await handler(request=req)
        assert result == "ok"
        mock_check.assert_called_once()
        # Identifier should be the client host
        assert mock_check.call_args.kwargs["identifier"] == "9.9.9.9"

    @pytest.mark.asyncio
    async def test_decorator_rate_limit_exceeded_raises_429(self):
        from fastapi import HTTPException

        req = _make_request()
        with patch.object(rl_mod._rate_limiter, "check_rate_limit") as mock_check:
            mock_check.return_value = (False, 0, 99999)

            @rate_limit(limit=10, window=60, scope="ip")
            async def handler(request):
                return "ok"

            with pytest.raises(HTTPException) as exc:
                await handler(request=req)
        assert exc.value.status_code == 429

    @pytest.mark.asyncio
    async def test_decorator_endpoint_scope(self):
        req = _make_request(path="/api/x", method="POST")
        with patch.object(rl_mod._rate_limiter, "check_rate_limit") as mock_check:
            mock_check.return_value = (True, 10, 99999)

            @rate_limit(scope="endpoint")
            async def handler(request):
                return "ok"

            await handler(request=req)
        assert mock_check.call_args.kwargs["identifier"] == "POST:/api/x"

    @pytest.mark.asyncio
    async def test_decorator_custom_key_func(self):
        req = _make_request()
        with patch.object(rl_mod._rate_limiter, "check_rate_limit") as mock_check:
            mock_check.return_value = (True, 10, 99999)

            @rate_limit(scope="user", key_func=lambda r: "custom-key")
            async def handler(request):
                return "ok"

            await handler(request=req)
        assert mock_check.call_args.kwargs["identifier"] == "custom-key"

    @pytest.mark.asyncio
    async def test_decorator_user_scope_no_auth_uses_ip(self):
        req = _make_request(host="5.5.5.5")
        with patch.object(rl_mod._rate_limiter, "check_rate_limit") as mock_check:
            mock_check.return_value = (True, 10, 99999)

            @rate_limit(scope="user")
            async def handler(request):
                return "ok"

            await handler(request=req)
        assert mock_check.call_args.kwargs["identifier"] == "5.5.5.5"
