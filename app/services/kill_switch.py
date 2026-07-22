"""Scan kill-switch — blast-radius emergency stop.

A global (or per-tenant) flag in Redis that halts scanning. The pipeline checks
it before starting and between phase groups, so an in-flight scan stops
gracefully; new scans abort immediately. This is the institutionalised
"don't take things down": one command stops everything.

Fail-open on the CHECK: if Redis is unreachable the switch reads as *inactive*
so a Redis blip can't silently freeze all scanning. Activation/deactivation
surface their errors to the caller.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from app.core.cache import _get_sync_redis

logger = logging.getLogger(__name__)

_GLOBAL_KEY = "easm:scan_killswitch"
_TENANT_KEY = "easm:scan_killswitch:tenant:{}"


def _key(tenant_id: Optional[int]) -> str:
    return _TENANT_KEY.format(tenant_id) if tenant_id is not None else _GLOBAL_KEY


def activate(reason: str = "manual", tenant_id: Optional[int] = None) -> None:
    """Engage the kill switch (global, or for a single tenant)."""
    _get_sync_redis().set(_key(tenant_id), reason or "manual")
    scope = f"tenant {tenant_id}" if tenant_id is not None else "GLOBAL"
    logger.warning("[kill-switch] ACTIVATED (%s): %s", scope, reason)


def deactivate(tenant_id: Optional[int] = None) -> None:
    """Release the kill switch."""
    _get_sync_redis().delete(_key(tenant_id))
    scope = f"tenant {tenant_id}" if tenant_id is not None else "GLOBAL"
    logger.warning("[kill-switch] released (%s)", scope)


def is_active(tenant_id: Optional[int] = None) -> Tuple[bool, str]:
    """Return (active, reason). The global switch or the tenant's switch trips it.

    Fail-open: on any Redis error, returns (False, "") so scanning continues.
    """
    try:
        r = _get_sync_redis()
        reason = r.get(_GLOBAL_KEY)
        if reason:
            return True, str(reason)
        if tenant_id is not None:
            reason = r.get(_TENANT_KEY.format(tenant_id))
            if reason:
                return True, str(reason)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("kill-switch check failed (treating as inactive): %s", exc)
    return False, ""
