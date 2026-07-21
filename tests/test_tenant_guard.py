"""Tests for the tenant-isolation context + ORM guard."""

import logging

import pytest
from unittest.mock import patch

from app.config import settings
from app.core.tenant_context import (
    allow_cross_tenant,
    get_current_tenant,
    is_cross_tenant_allowed,
    mark_cross_tenant,
    reset_tenant_context,
    tenant_scope,
)
from app.core.tenant_guard import TenantIsolationError
from app.models.database import Asset, Tenant


@pytest.fixture(autouse=True)
def _clean_context():
    """Contextvars persist across tests in one thread — reset around each."""
    reset_tenant_context()
    yield
    reset_tenant_context()


class TestTenantContext:
    def test_scope_sets_and_restores(self):
        assert get_current_tenant() is None
        with tenant_scope(7):
            assert get_current_tenant() == 7
        assert get_current_tenant() is None

    def test_allow_cross_tenant_block(self):
        assert is_cross_tenant_allowed() is False
        with allow_cross_tenant():
            assert is_cross_tenant_allowed() is True
        assert is_cross_tenant_allowed() is False

    def test_mark_and_reset(self):
        mark_cross_tenant()
        assert is_cross_tenant_allowed() is True
        reset_tenant_context()
        assert is_cross_tenant_allowed() is False
        assert get_current_tenant() is None


class TestGuardEnforce:
    def test_scoped_query_without_context_raises(self, db_session):
        with patch.object(settings, "tenant_guard_mode", "enforce"):
            with pytest.raises(TenantIsolationError):
                db_session.query(Asset).all()

    def test_context_allows_scoped_query(self, db_session, tenant):
        with patch.object(settings, "tenant_guard_mode", "enforce"):
            with tenant_scope(tenant.id):
                db_session.query(Asset).all()  # must not raise

    def test_cross_tenant_allows_scoped_query(self, db_session):
        with patch.object(settings, "tenant_guard_mode", "enforce"):
            with allow_cross_tenant():
                db_session.query(Asset).all()  # must not raise

    def test_non_scoped_model_ignored(self, db_session):
        # Tenant itself has no tenant_id → not guarded.
        with patch.object(settings, "tenant_guard_mode", "enforce"):
            db_session.query(Tenant).all()  # must not raise


class TestGuardAudit:
    def test_audit_logs_but_does_not_raise(self, db_session, caplog):
        with patch.object(settings, "tenant_guard_mode", "audit"):
            with caplog.at_level(logging.WARNING, logger="app.core.tenant_guard"):
                db_session.query(Asset).all()  # must not raise
        assert any("tenant-guard" in r.message or "tenant-scoped" in r.message for r in caplog.records)

    def test_off_mode_silent(self, db_session, caplog):
        with patch.object(settings, "tenant_guard_mode", "off"):
            with caplog.at_level(logging.WARNING, logger="app.core.tenant_guard"):
                db_session.query(Asset).all()
        assert not any("tenant-guard" in r.message for r in caplog.records)
