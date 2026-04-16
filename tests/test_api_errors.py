"""
Unit tests for app/api/errors.py

Covers:
- Custom exception classes (APIError, AuthenticationError, AuthorizationError,
  NotFoundError, ValidationError, RateLimitError, TenantError)
- create_error_response: basic shape, with details, with trace
- api_error_handler: returns expected JSON
- http_exception_handler: 4xx/5xx handling, audit log 401/403
- validation_exception_handler: error list construction
- jwt_error_handler: ExpiredSignatureError vs InvalidTokenError
- generic_exception_handler: generic 500
- register_error_handlers: adds all handlers
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as jwtlib
import pytest

from app.api import errors as errors_mod
from app.api.errors import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    TenantError,
    ValidationError as APIValidationError,
    api_error_handler,
    create_error_response,
    generic_exception_handler,
    http_exception_handler,
    jwt_error_handler,
    register_error_handlers,
    validation_exception_handler,
)


def _mk_request(path="/api/v1/assets", method="GET", client_host="1.2.3.4"):
    req = MagicMock()
    req.url = MagicMock()
    req.url.path = path
    req.method = method
    req.client = MagicMock()
    req.client.host = client_host
    return req


class TestCustomExceptions:
    def test_api_error_defaults(self):
        e = APIError("boom")
        assert e.status_code == 500
        assert e.message == "boom"
        assert e.error_code == "INTERNAL_ERROR"
        assert e.details == {}

    def test_api_error_custom(self):
        e = APIError("x", status_code=418, details={"a": 1}, error_code="TEAPOT")
        assert e.status_code == 418
        assert e.details == {"a": 1}
        assert e.error_code == "TEAPOT"

    def test_authentication_error(self):
        e = AuthenticationError()
        assert e.status_code == 401
        assert e.error_code == "AUTH_REQUIRED"

    def test_authorization_error(self):
        e = AuthorizationError()
        assert e.status_code == 403
        assert e.error_code == "INSUFFICIENT_PERMISSIONS"

    def test_not_found_error_basic(self):
        e = NotFoundError("Asset")
        assert e.status_code == 404
        assert "Asset" in e.message
        assert e.error_code == "NOT_FOUND"

    def test_not_found_error_with_id(self):
        e = NotFoundError("Finding", resource_id=42)
        assert "42" in e.message

    def test_validation_error(self):
        e = APIValidationError("Bad input", details={"field": "x"})
        assert e.status_code == 422
        assert e.error_code == "VALIDATION_ERROR"

    def test_rate_limit_error(self):
        e = RateLimitError(retry_after=120)
        assert e.status_code == 429
        assert e.details["retry_after"] == 120

    def test_tenant_error(self):
        e = TenantError()
        assert e.status_code == 403
        assert e.error_code == "TENANT_ACCESS_DENIED"


class TestCreateErrorResponse:
    def _body(self, response):
        return json.loads(response.body.decode())

    def test_basic_shape(self):
        r = create_error_response("msg", 400, "CODE")
        body = self._body(r)
        assert r.status_code == 400
        assert body["error"]["code"] == "CODE"
        assert body["error"]["message"] == "msg"

    def test_with_details(self):
        r = create_error_response("msg", 422, "VAL", details={"field": "x"})
        body = self._body(r)
        assert body["error"]["details"] == {"field": "x"}

    def test_with_trace(self):
        try:
            raise RuntimeError("simulated")
        except RuntimeError:
            r = create_error_response("msg", 500, "ERR", include_trace=True)
        body = self._body(r)
        assert "trace" in body["error"]


class TestApiErrorHandler:
    @pytest.mark.asyncio
    async def test_returns_proper_response(self):
        req = _mk_request()
        exc = APIError("boom", status_code=400, error_code="BAD", details={"a": 1})
        r = await api_error_handler(req, exc)
        assert r.status_code == 400
        body = json.loads(r.body.decode())
        assert body["error"]["code"] == "BAD"
        assert body["error"]["details"] == {"a": 1}


class TestHttpExceptionHandler:
    @pytest.mark.asyncio
    async def test_404(self):
        req = _mk_request()
        from starlette.exceptions import HTTPException

        exc = HTTPException(status_code=404, detail="Not found")
        with patch.object(errors_mod, "log_audit_event"):
            r = await http_exception_handler(req, exc)
        assert r.status_code == 404
        body = json.loads(r.body.decode())
        assert body["error"]["code"] == "HTTP_404"

    @pytest.mark.asyncio
    async def test_401_triggers_audit_log(self):
        req = _mk_request()
        from starlette.exceptions import HTTPException

        exc = HTTPException(status_code=401, detail="Unauthorized")
        with patch.object(errors_mod, "log_audit_event") as mock_audit:
            r = await http_exception_handler(req, exc)
        assert r.status_code == 401
        assert mock_audit.called

    @pytest.mark.asyncio
    async def test_403_triggers_audit_log(self):
        req = _mk_request()
        from starlette.exceptions import HTTPException

        exc = HTTPException(status_code=403, detail="Forbidden")
        with patch.object(errors_mod, "log_audit_event") as mock_audit:
            await http_exception_handler(req, exc)
        assert mock_audit.called

    @pytest.mark.asyncio
    async def test_500_no_audit(self):
        req = _mk_request()
        from starlette.exceptions import HTTPException

        exc = HTTPException(status_code=500, detail="Boom")
        with patch.object(errors_mod, "log_audit_event") as mock_audit:
            await http_exception_handler(req, exc)
        assert not mock_audit.called

    @pytest.mark.asyncio
    async def test_audit_log_failure_does_not_propagate(self):
        req = _mk_request()
        from starlette.exceptions import HTTPException

        exc = HTTPException(status_code=401, detail="x")
        with patch.object(errors_mod, "log_audit_event", side_effect=RuntimeError("audit down")):
            r = await http_exception_handler(req, exc)
        # Still returns a valid response
        assert r.status_code == 401


class TestValidationExceptionHandler:
    @pytest.mark.asyncio
    async def test_builds_error_list(self):
        req = _mk_request()
        exc = MagicMock()
        exc.errors = MagicMock(
            return_value=[
                {"loc": ("body", "field"), "msg": "too short", "type": "value_error"},
                {"loc": ("body", "other"), "msg": "invalid", "type": "type_error"},
            ]
        )
        r = await validation_exception_handler(req, exc)
        body = json.loads(r.body.decode())
        assert r.status_code == 422
        assert body["error"]["code"] == "VALIDATION_ERROR"
        errs = body["error"]["details"]["errors"]
        assert len(errs) == 2
        assert errs[0]["field"] == "body.field"


class TestJwtErrorHandler:
    @pytest.mark.asyncio
    async def test_expired_token(self):
        req = _mk_request()
        with patch.object(errors_mod, "log_audit_event"):
            r = await jwt_error_handler(req, jwtlib.ExpiredSignatureError("expired"))
        body = json.loads(r.body.decode())
        assert body["error"]["code"] == "TOKEN_EXPIRED"
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token(self):
        req = _mk_request()
        with patch.object(errors_mod, "log_audit_event"):
            r = await jwt_error_handler(req, jwtlib.InvalidTokenError("bad"))
        body = json.loads(r.body.decode())
        assert body["error"]["code"] == "TOKEN_INVALID"

    @pytest.mark.asyncio
    async def test_audit_log_failure_handled(self):
        req = _mk_request()
        with patch.object(errors_mod, "log_audit_event", side_effect=RuntimeError("x")):
            r = await jwt_error_handler(req, jwtlib.InvalidTokenError("bad"))
        assert r.status_code == 401


class TestGenericExceptionHandler:
    @pytest.mark.asyncio
    async def test_returns_generic_500(self):
        req = _mk_request()
        with patch.object(errors_mod, "log_audit_event"):
            r = await generic_exception_handler(req, RuntimeError("secret internal info"))
        body = json.loads(r.body.decode())
        assert r.status_code == 500
        assert body["error"]["code"] == "INTERNAL_ERROR"
        # Ensure secret is NOT leaked in message
        assert "secret internal info" not in body["error"]["message"]

    @pytest.mark.asyncio
    async def test_audit_failure_not_propagated(self):
        req = _mk_request()
        with patch.object(errors_mod, "log_audit_event", side_effect=RuntimeError("audit down")):
            r = await generic_exception_handler(req, RuntimeError("x"))
        assert r.status_code == 500


class TestRegisterHandlers:
    def test_registers_handlers(self):
        app = MagicMock()
        register_error_handlers(app)
        # Should register 5 handlers
        assert app.add_exception_handler.call_count == 5
