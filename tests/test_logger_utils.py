"""Tests for logger utility (app/utils/logger.py).

Covers:
- JSONFormatter output shape
- _parse_size unit parsing
- get_logger returns a Logger
- TenantLoggerAdapter merges extra
- _filter_sensitive_data redacts secrets
- setup_sentry no-op without dsn
"""

from __future__ import annotations

import json
import logging

from app.utils.logger import (
    JSONFormatter,
    TenantLoggerAdapter,
    _filter_sensitive_data,
    _parse_size,
    get_logger,
    setup_sentry,
)


class TestParseSize:
    def test_gb_parsing(self):
        assert _parse_size("1GB") == 1 * 1024 * 1024 * 1024
        assert _parse_size("2GB") == 2 * 1024 * 1024 * 1024

    def test_mb_parsing(self):
        assert _parse_size("100MB") == 100 * 1024 * 1024

    def test_kb_parsing(self):
        assert _parse_size("64KB") == 64 * 1024

    def test_raw_bytes(self):
        assert _parse_size("1000") == 1000

    def test_case_insensitive(self):
        assert _parse_size("1gb") == 1024 * 1024 * 1024
        assert _parse_size("100mb") == 100 * 1024 * 1024

    def test_whitespace_stripped(self):
        assert _parse_size("  100MB  ") == 100 * 1024 * 1024


class TestJSONFormatter:
    def _record(self, msg="test"):
        return logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="/fake.py",
            lineno=42,
            msg=msg,
            args=None,
            exc_info=None,
            func="test_func",
        )

    def test_returns_valid_json(self):
        fmt = JSONFormatter()
        rec = self._record()
        out = fmt.format(rec)
        data = json.loads(out)
        assert data["message"] == "test"
        assert data["level"] == "INFO"
        assert data["logger"] == "test.module"
        assert data["line"] == 42

    def test_includes_tenant_id_extra(self):
        fmt = JSONFormatter()
        rec = self._record()
        rec.tenant_id = 7
        out = fmt.format(rec)
        data = json.loads(out)
        assert data["tenant_id"] == 7

    def test_includes_multiple_extras(self):
        fmt = JSONFormatter()
        rec = self._record()
        rec.tenant_id = 1
        rec.asset_id = 2
        rec.task_id = "t-1"
        rec.request_id = "req-1"
        rec.scan_run_id = 42
        rec.phase = "discovery"
        out = json.loads(fmt.format(rec))
        assert out["asset_id"] == 2
        assert out["task_id"] == "t-1"
        assert out["request_id"] == "req-1"
        assert out["scan_run_id"] == 42
        assert out["phase"] == "discovery"

    def test_includes_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("oops")
        except ValueError:
            import sys

            rec = logging.LogRecord(
                name="t",
                level=logging.ERROR,
                pathname="/fake.py",
                lineno=1,
                msg="failed",
                args=None,
                exc_info=sys.exc_info(),
            )
        out = json.loads(fmt.format(rec))
        assert "exception" in out
        assert "ValueError" in out["exception"]


class TestGetLogger:
    def test_returns_logger_instance(self):
        lg = get_logger("test.module.x")
        assert isinstance(lg, logging.Logger)
        assert lg.name == "test.module.x"

    def test_same_name_same_instance(self):
        a = get_logger("same.name")
        b = get_logger("same.name")
        assert a is b


class TestTenantLoggerAdapter:
    def test_adapter_adds_extra(self):
        base = logging.getLogger("tenant-test")
        adapter = TenantLoggerAdapter(base, {"tenant_id": 42})
        msg, kwargs = adapter.process("hello", {})
        assert kwargs["extra"]["tenant_id"] == 42
        assert msg == "hello"

    def test_merges_existing_extra(self):
        base = logging.getLogger("tenant-test2")
        adapter = TenantLoggerAdapter(base, {"tenant_id": 1})
        msg, kwargs = adapter.process("hi", {"extra": {"other_field": "foo"}})
        assert kwargs["extra"]["tenant_id"] == 1
        assert kwargs["extra"]["other_field"] == "foo"


class TestFilterSensitiveData:
    def test_redacts_secret_key(self):
        event = {
            "contexts": {
                "environment": {
                    "SECRET_KEY": "my-real-secret",
                    "APP_ENV": "prod",
                }
            }
        }
        out = _filter_sensitive_data(event, {})
        assert out["contexts"]["environment"]["SECRET_KEY"] == "[REDACTED]"
        assert out["contexts"]["environment"]["APP_ENV"] == "prod"

    def test_redacts_jwt_secret_key(self):
        event = {"contexts": {"environment": {"JWT_SECRET_KEY": "token"}}}
        out = _filter_sensitive_data(event, {})
        assert out["contexts"]["environment"]["JWT_SECRET_KEY"] == "[REDACTED]"

    def test_redacts_password_and_api_key(self):
        event = {
            "contexts": {
                "environment": {
                    "USER_PASSWORD": "pw",
                    "API_KEY": "abcdef",
                }
            }
        }
        out = _filter_sensitive_data(event, {})
        assert out["contexts"]["environment"]["USER_PASSWORD"] == "[REDACTED]"
        assert out["contexts"]["environment"]["API_KEY"] == "[REDACTED]"

    def test_preserves_non_sensitive_fields(self):
        event = {"contexts": {"environment": {"HOSTNAME": "srv01"}}}
        out = _filter_sensitive_data(event, {})
        assert out["contexts"]["environment"]["HOSTNAME"] == "srv01"

    def test_no_environment_context_is_noop(self):
        event = {"contexts": {"other": {}}}
        out = _filter_sensitive_data(event, {})
        assert out == event


class TestSetupSentry:
    def test_no_dsn_is_noop(self):
        # Should return None without raising
        assert setup_sentry(dsn=None) is None
        assert setup_sentry(dsn="") is None
