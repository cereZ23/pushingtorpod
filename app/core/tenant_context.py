"""Request/task-scoped tenant context.

Tenant isolation is enforced today only by convention (every query filters
``tenant_id`` by hand). This module holds the *current* tenant for the running
request or Celery task in a ``ContextVar`, so a defense-in-depth guard (see
``app.core.tenant_guard``) — and later Postgres RLS — can verify that queries
against tenant-scoped tables actually run under a known tenant, instead of
trusting every call site to remember the filter.

Nothing here changes query behaviour on its own; it only records intent.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Iterator, Optional

# The tenant the current logical operation is scoped to (None = not set).
_current_tenant: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar("current_tenant_id", default=None)

# Explicit opt-out for legitimately cross-tenant work (superuser endpoints,
# background jobs that iterate all tenants, retention cleanup, global caches).
_allow_cross_tenant: contextvars.ContextVar[bool] = contextvars.ContextVar("allow_cross_tenant", default=False)


def set_current_tenant(tenant_id: Optional[int]) -> None:
    """Set the active tenant for the current context (request/task)."""
    _current_tenant.set(tenant_id)


def get_current_tenant() -> Optional[int]:
    """Return the active tenant id, or None if none is set."""
    return _current_tenant.get()


def clear_current_tenant() -> None:
    """Clear the active tenant (e.g. at the end of a task)."""
    _current_tenant.set(None)


def is_cross_tenant_allowed() -> bool:
    """True inside an ``allow_cross_tenant()`` block (or after ``mark_cross_tenant``)."""
    return _allow_cross_tenant.get()


def mark_cross_tenant() -> None:
    """Flag the whole current operation as cross-tenant (no matching reset).

    For genuinely tenant-agnostic Celery tasks that run cross-tenant end to end
    (retention cleanup, global CVE cache, all-tenant sync/scoring). Cleared by
    ``reset_tenant_context`` at task teardown.
    """
    _allow_cross_tenant.set(True)


def reset_tenant_context() -> None:
    """Clear both the tenant and cross-tenant flags (call at task teardown)."""
    _current_tenant.set(None)
    _allow_cross_tenant.set(False)


@contextmanager
def tenant_scope(tenant_id: int) -> Iterator[None]:
    """Run a block scoped to ``tenant_id`` (restores the previous value after)."""
    token = _current_tenant.set(tenant_id)
    try:
        yield
    finally:
        _current_tenant.reset(token)


@contextmanager
def allow_cross_tenant() -> Iterator[None]:
    """Mark a block as intentionally cross-tenant so the isolation guard allows it.

    Use ONLY for genuinely tenant-agnostic work (superuser access, all-tenant
    background jobs, global caches, retention cleanup). Keep the block as small
    as possible.
    """
    token = _allow_cross_tenant.set(True)
    try:
        yield
    finally:
        _allow_cross_tenant.reset(token)
