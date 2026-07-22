"""Tests for the RLS tenant-GUC connection wiring (_apply_tenant_guc)."""

from unittest.mock import MagicMock

import pytest

from app.core.tenant_context import allow_cross_tenant, reset_tenant_context, tenant_scope
from app.database import _apply_tenant_guc


@pytest.fixture(autouse=True)
def _clean():
    reset_tenant_context()
    yield
    reset_tenant_context()


def _invoke(cursor):
    _apply_tenant_guc(None, cursor, "SELECT 1", (), None, False)


def _values(cursor):
    # each cursor.execute(stmt, params) -> params is a 1-tuple; return the two values
    calls = cursor.execute.call_args_list
    return calls[0].args[1][0], calls[1].args[1][0]


def test_sets_tenant_id_and_cross_off():
    cur = MagicMock()
    with tenant_scope(5):
        _invoke(cur)
    tid, cross = _values(cur)
    assert tid == "5"
    assert cross == "off"


def test_cross_tenant_flag_on():
    cur = MagicMock()
    with allow_cross_tenant():
        _invoke(cur)
    _tid, cross = _values(cur)
    assert cross == "on"


def test_no_context_sets_empty_tenant():
    cur = MagicMock()
    _invoke(cur)
    tid, cross = _values(cur)
    assert tid == ""
    assert cross == "off"


def test_never_raises_on_cursor_error():
    cur = MagicMock()
    cur.execute.side_effect = RuntimeError("boom")
    # must be swallowed (fail-open) — a GUC error must never break a query
    _invoke(cur)
