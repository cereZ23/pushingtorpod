"""Scope-authorization enforcement.

Before actively scanning/probing a target, verify it falls within an active,
in-window ScanAuthorization for the tenant. This is the legal gate: it prevents
a wrong scope, a typo, or a crt.sh/DNS result from pointing an active scan at a
party that never authorized it.

Rolled out in "audit" mode first (log out-of-scope targets, don't block —
behaviour-preserving), like the tenant guard; flip to "enforce" once the audit
log confirms real scans are covered.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from app.config import settings
from app.models.authorization import ScanAuthorization

logger = logging.getLogger(__name__)


class ScopeViolationError(RuntimeError):
    """Raised (enforce mode) when a scan target is outside every authorization."""


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None


def _domain_in_scope(target: str, scope_value: str) -> bool:
    t = (target or "").strip().strip(".").lower()
    s = (scope_value or "").strip().strip(".").lower()
    return bool(s) and (t == s or t.endswith("." + s))


def _ip_in_scope(ip, entry_type: str, scope_value: str) -> bool:
    try:
        if entry_type == "ip":
            return ip == ipaddress.ip_address(scope_value.strip())
        if entry_type == "cidr":
            return ip in ipaddress.ip_network(scope_value.strip(), strict=False)
    except (ValueError, TypeError):
        return False
    return False


def target_in_scope(target: str, scope_entries: List[dict]) -> bool:
    """True if ``target`` (a domain or IP) matches any scope entry.

    A domain entry covers the domain and all its subdomains; ip/cidr entries
    match IP targets exactly / by network.
    """
    if not target or not scope_entries:
        return False
    ip = _as_ip(target)
    for entry in scope_entries:
        etype = (entry or {}).get("type")
        evalue = (entry or {}).get("value", "")
        if not evalue:
            continue
        if ip is None and etype == "domain" and _domain_in_scope(target, evalue):
            return True
        if ip is not None and etype in ("ip", "cidr") and _ip_in_scope(ip, etype, evalue):
            return True
    return False


def _active_authorizations(db: Any, tenant_id: int, now: datetime) -> List[ScanAuthorization]:
    auths = (
        db.query(ScanAuthorization)
        .filter(ScanAuthorization.tenant_id == tenant_id, ScanAuthorization.is_active.is_(True))
        .all()
    )
    live = []
    for a in auths:
        if a.valid_from and a.valid_from > now:
            continue
        if a.valid_until and a.valid_until < now:
            continue
        live.append(a)
    return live


def is_target_authorized(db: Any, tenant_id: int, target: str, now: Optional[datetime] = None) -> bool:
    now = now or datetime.now(timezone.utc)
    for auth in _active_authorizations(db, tenant_id, now):
        if target_in_scope(target, auth.scope_entries or []):
            return True
    return False


def assert_targets_authorized(
    db: Any,
    tenant_id: int,
    targets: List[str],
    now: Optional[datetime] = None,
    mode: Optional[str] = None,
) -> List[str]:
    """Check targets against the tenant's authorizations.

    Returns the list of out-of-scope targets. In "enforce" mode raises
    ``ScopeViolationError`` if any are out of scope; in "audit" mode logs them;
    "off" disables the check.
    """
    mode = mode or getattr(settings, "scope_enforcement_mode", "audit")
    if mode == "off":
        return []
    now = now or datetime.now(timezone.utc)
    active = _active_authorizations(db, tenant_id, now)
    out_of_scope = [t for t in targets if not any(target_in_scope(t, a.scope_entries or []) for a in active)]
    if out_of_scope:
        message = (
            f"tenant {tenant_id}: {len(out_of_scope)} scan target(s) outside authorized scope: {out_of_scope[:10]}"
        )
        if mode == "enforce":
            raise ScopeViolationError(message)
        logger.warning("[scope-auth] %s", message)
    return out_of_scope
