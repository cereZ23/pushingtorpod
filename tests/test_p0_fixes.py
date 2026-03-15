"""
Tests for P0 fixes applied 2026-03-15.

Covers:
1. Redis exception specificity in auth lockout functions (auth.py)
2. Consistent error return from RiskScoringEngine.calculate_asset_risk (risk_scoring.py)
3. ORM relationship declarations: Asset.certificates / Asset.endpoints (database.py, enrichment.py)
4. Audit logging wired into projects.py and assets.py mutation endpoints
"""

from __future__ import annotations

import logging

import pytest
from unittest.mock import MagicMock, patch

from app.api.routers.auth import (
    _check_account_lockout,
    _record_login_failure,
    _clear_login_failures,
    _check_mfa_lockout,
    _record_mfa_failure,
    _clear_mfa_failures,
)
from app.models.database import Asset
from app.models.enrichment import Certificate, Endpoint
from app.services.risk_scoring import RiskScoringEngine


# ---------------------------------------------------------------------------
# 1. Redis exception specificity — verify each specific exception type
#    is caught and fails open (no raise), logged at ERROR level
# ---------------------------------------------------------------------------


class TestRedisExceptionSpecificity:
    """Lockout functions must catch specific Redis exceptions, not bare Exception."""

    @patch("app.api.routers.auth._get_redis")
    def test_check_lockout_catches_redis_connection_error(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.ConnectionError("Connection refused")
        _check_account_lockout("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_check_lockout_catches_redis_timeout_error(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.TimeoutError("Read timed out")
        _check_account_lockout("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_check_lockout_catches_os_error(self, mock_get_redis):
        mock_get_redis.side_effect = OSError("Network unreachable")
        _check_account_lockout("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_check_lockout_catches_redis_error(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.RedisError("READONLY mode")
        _check_account_lockout("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_record_failure_catches_redis_timeout(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.TimeoutError("timeout")
        _record_login_failure("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_clear_failures_catches_redis_error(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.RedisError("NOSCRIPT")
        _clear_login_failures("user@test.com")

    @patch("app.api.routers.auth._get_redis")
    def test_mfa_lockout_catches_redis_timeout(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.TimeoutError("timeout")
        _check_mfa_lockout(42)

    @patch("app.api.routers.auth._get_redis")
    def test_mfa_record_catches_os_error(self, mock_get_redis):
        mock_get_redis.side_effect = OSError("Connection reset")
        _record_mfa_failure(42)

    @patch("app.api.routers.auth._get_redis")
    def test_mfa_clear_catches_redis_connection_error(self, mock_get_redis):
        import redis as _redis

        mock_get_redis.side_effect = _redis.ConnectionError("refused")
        _clear_mfa_failures(42)

    @patch("app.api.routers.auth._get_redis")
    def test_check_lockout_logs_at_error_level(self, mock_get_redis, caplog):
        """Redis failures must be logged at ERROR, not WARNING."""
        import redis as _redis

        mock_get_redis.side_effect = _redis.ConnectionError("refused")

        with caplog.at_level(logging.ERROR, logger="app.api.routers.auth"):
            _check_account_lockout("user@test.com")

        redis_records = [r for r in caplog.records if "Redis" in r.message]
        assert len(redis_records) >= 1
        assert all(r.levelno >= logging.ERROR for r in redis_records)

    @patch("app.api.routers.auth._get_redis")
    def test_record_failure_logs_at_error_level(self, mock_get_redis, caplog):
        import redis as _redis

        mock_get_redis.side_effect = _redis.TimeoutError("timeout")

        with caplog.at_level(logging.ERROR, logger="app.api.routers.auth"):
            _record_login_failure("user@test.com")

        redis_records = [r for r in caplog.records if "Redis" in r.message]
        assert len(redis_records) >= 1
        assert all(r.levelno >= logging.ERROR for r in redis_records)


# ---------------------------------------------------------------------------
# 2. Risk scoring — consistent error return when asset not found
# ---------------------------------------------------------------------------


class TestRiskScoringErrorReturn:
    """calculate_asset_risk must return all expected keys when asset is missing."""

    EXPECTED_KEYS = {
        "asset_id",
        "asset_identifier",
        "risk_score",
        "risk_level",
        "components",
        "recommendations",
        "error",
    }

    def _engine_with_missing_asset(self) -> tuple[RiskScoringEngine, dict]:
        mock_db = MagicMock()
        mock_db.query.return_value.filter_by.return_value.first.return_value = None
        engine = RiskScoringEngine(mock_db)
        return engine, engine.calculate_asset_risk(99999)

    def test_returns_all_expected_keys(self):
        _, result = self._engine_with_missing_asset()
        assert set(result.keys()) == self.EXPECTED_KEYS

    def test_default_values(self):
        _, result = self._engine_with_missing_asset()
        assert result["asset_id"] == 99999
        assert result["asset_identifier"] is None
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "info"
        assert result["components"] == {}
        assert result["recommendations"] == []
        assert result["error"] == "asset_not_found"

    def test_no_key_error_on_caller_access(self):
        """Callers accessing any standard key must not get KeyError."""
        _, result = self._engine_with_missing_asset()
        for key in self.EXPECTED_KEYS:
            _ = result[key]  # would raise KeyError before fix


# ---------------------------------------------------------------------------
# 3. ORM relationships — Asset.certificates / Asset.endpoints
# ---------------------------------------------------------------------------


class TestAssetEnrichmentRelationships:
    """Verify relationship declarations between Asset ↔ Certificate/Endpoint."""

    def test_asset_has_certificates_relationship(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert "certificates" in {r.key for r in mapper.relationships}

    def test_asset_has_endpoints_relationship(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert "endpoints" in {r.key for r in mapper.relationships}

    def test_certificate_has_asset_backref(self):
        from sqlalchemy import inspect

        mapper = inspect(Certificate)
        assert "asset" in {r.key for r in mapper.relationships}

    def test_endpoint_has_asset_backref(self):
        from sqlalchemy import inspect

        mapper = inspect(Endpoint)
        assert "asset" in {r.key for r in mapper.relationships}

    def test_certificates_target_is_certificate_model(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert mapper.relationships["certificates"].mapper.class_ is Certificate

    def test_endpoints_target_is_endpoint_model(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert mapper.relationships["endpoints"].mapper.class_ is Endpoint

    def test_certificates_cascade_includes_delete(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert "delete" in mapper.relationships["certificates"].cascade

    def test_endpoints_cascade_includes_delete(self):
        from sqlalchemy import inspect

        mapper = inspect(Asset)
        assert "delete" in mapper.relationships["endpoints"].cascade


# ---------------------------------------------------------------------------
# 4. Audit logging wired into projects.py mutation endpoints
# ---------------------------------------------------------------------------


class TestProjectsAuditLogging:
    """Verify projects.py mutation endpoints call audit functions (source-level)."""

    def test_trigger_scan_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.trigger_scan)
        assert "log_audit_event" in source
        assert "AuditEventType.DATA_CREATE" in source

    def test_cancel_scan_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.cancel_scan_run)
        assert "log_audit_event" in source
        assert "AuditEventType.CONFIG_CHANGE" in source

    def test_add_scope_rule_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.add_scope_rule)
        assert "log_data_modification" in source

    def test_create_profile_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.create_scan_profile)
        assert "log_data_modification" in source

    def test_update_profile_schedule_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.update_profile_schedule)
        assert "log_data_modification" in source

    def test_delete_scan_run_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.delete_scan_run_by_id)
        assert "log_data_modification" in source

    def test_cancel_scan_run_by_id_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects.cancel_scan_run_by_id)
        assert "log_audit_event" in source


class TestAssetsAuditLogging:
    """Verify assets.py mutation endpoints call audit functions (source-level)."""

    def test_rescan_asset_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets.rescan_asset)
        assert "log_audit_event" in source
        assert "AuditEventType.DATA_UPDATE" in source

    def test_trigger_screenshot_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets.trigger_asset_screenshot)
        assert "log_audit_event" in source
        assert "AuditEventType.DATA_CREATE" in source

    def test_create_asset_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets.create_asset)
        assert "log_data_modification" in source

    def test_update_asset_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets.update_asset)
        assert "log_data_modification" in source

    def test_delete_asset_calls_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets.delete_asset)
        assert "log_data_modification" in source


class TestAuditImports:
    """Verify audit functions are imported in routers that need them."""

    def test_projects_imports_audit(self):
        import inspect as _inspect
        from app.api.routers import projects

        source = _inspect.getsource(projects)
        assert "from app.core.audit import" in source
        assert "log_data_modification" in source
        assert "log_audit_event" in source
        assert "AuditEventType" in source

    def test_assets_imports_audit(self):
        import inspect as _inspect
        from app.api.routers import assets

        source = _inspect.getsource(assets)
        assert "from app.core.audit import" in source
        assert "log_data_modification" in source
        assert "log_audit_event" in source
        assert "AuditEventType" in source
