"""Defense-in-depth tenant-isolation guard at the ORM layer.

Fires on every ORM SELECT/UPDATE/DELETE. If the statement touches a
tenant-scoped table but no tenant context is active (``tenant_context``) and the
work is not explicitly marked cross-tenant, it is a potential isolation gap.

Modes (``settings.tenant_guard_mode``):
  - ``"audit"``  (default): log the violation, do NOT block. Behaviour-preserving
    — safe to ship to production; it just reveals the query paths that don't yet
    establish a tenant context (the ones to fix before enforcement / RLS).
  - ``"enforce"``: raise ``TenantIsolationError``.
  - ``"off"``: disabled.

This is the runtime precursor to Postgres RLS: it uses the same tenant context
that will later be pushed into a ``SET app.current_tenant_id`` GUC.
"""

from __future__ import annotations

import logging
from typing import Optional, Set

from sqlalchemy import event
from sqlalchemy.orm import Mapper, ORMExecuteState, Session

from app.config import settings
from app.core.tenant_context import get_current_tenant, is_cross_tenant_allowed

logger = logging.getLogger(__name__)

# Tenant-scoped tables WITHOUT a direct ``tenant_id`` column (reached via FK).
# Kept by name to avoid import cycles; matched against mapped class names.
_TRANSITIVE_SCOPED_NAMES: Set[str] = {
    "Service",
    "Finding",
    "Event",
    "Certificate",
    "Endpoint",
    "Scope",
    "ScanProfile",
    "PhaseResult",
    "IssueFinding",
    "IssueActivity",
}

# Access-control tables: they carry tenant_id but are governed by the auth flow
# (a user's memberships/keys legitimately span tenants), not by tenant-data
# isolation. Excluded from the guard — consistent with their RLS exclusion.
_EXCLUDED_NAMES: Set[str] = {"TenantMembership", "APIKey", "UserInvitation"}

_scoped_classes: Optional[Set[type]] = None


class TenantIsolationError(RuntimeError):
    """Raised (in enforce mode) when a tenant-scoped query runs with no tenant context."""


def _build_scoped_registry() -> Set[type]:
    """All mapped classes that are tenant-scoped (direct tenant_id or transitive)."""
    from app.models.database import Base

    scoped: Set[type] = set()
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        if cls.__name__ in _EXCLUDED_NAMES:
            continue
        if "tenant_id" in mapper.columns or cls.__name__ in _TRANSITIVE_SCOPED_NAMES:
            scoped.add(cls)
    return scoped


def _scoped_registry() -> Set[type]:
    global _scoped_classes
    if _scoped_classes is None:
        _scoped_classes = _build_scoped_registry()
    return _scoped_classes


def _statement_touches_tenant_table(state: ORMExecuteState) -> list[str]:
    """Names of tenant-scoped entities the statement targets (empty if none)."""
    scoped = _scoped_registry()
    hits: list[str] = []
    for mapper in state.all_mappers:
        if isinstance(mapper, Mapper) and mapper.class_ in scoped:
            hits.append(mapper.class_.__name__)
    return hits


@event.listens_for(Session, "do_orm_execute")
def _tenant_isolation_guard(state: ORMExecuteState) -> None:
    # The guard runs on EVERY ORM query, so it must never break a query through
    # an internal bug: fail open. Only the intentional TenantIsolationError
    # (enforce mode) is allowed to propagate.
    mode = getattr(settings, "tenant_guard_mode", "audit")
    if mode == "off":
        return
    try:
        if not (state.is_select or state.is_update or state.is_delete):
            return
        if is_cross_tenant_allowed() or get_current_tenant() is not None:
            return
        entities = _statement_touches_tenant_table(state)
        if not entities:
            return
        op = "SELECT" if state.is_select else ("UPDATE" if state.is_update else "DELETE")
        message = (
            f"tenant-scoped {op} on {', '.join(sorted(set(entities)))} with no active tenant context "
            "(wrap the call in tenant_scope(tenant_id) or, if intentional, allow_cross_tenant())"
        )
    except Exception as exc:  # never let a guard bug break a query
        logger.debug("tenant guard skipped (internal error): %s", exc)
        return

    if mode == "enforce":
        raise TenantIsolationError(message)
    logger.warning("[tenant-guard] %s", message)


def register_tenant_guard() -> None:
    """No-op hook to make the import-time listener registration explicit.

    Importing this module registers the ``do_orm_execute`` listener via the
    decorator above; call this from startup to document the dependency.
    """
    logger.info("Tenant isolation guard active (mode=%s)", getattr(settings, "tenant_guard_mode", "audit"))
