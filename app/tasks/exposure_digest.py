"""Weekly exposure-digest delivery (retention).

Beat task: for each tenant, compose the exposure digest and, if there's
something noteworthy, email it to the tenant's active members. Gated OFF by
default (``weekly_digest_enabled``) — enabling it starts emailing customers.
"""

from __future__ import annotations

import logging

from app.celery_app import celery
from app.config import settings
from app.core.tenant_context import allow_cross_tenant, mark_cross_tenant, tenant_scope
from app.database import SessionLocal

logger = logging.getLogger(__name__)


def _tenant_recipients(db, tenant_id: int) -> list[str]:
    from app.models.auth import TenantMembership, User

    rows = (
        db.query(User.email)
        .join(TenantMembership, TenantMembership.user_id == User.id)
        .filter(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.is_active.is_(True),
            User.is_active.is_(True),
        )
        .all()
    )
    return [r[0] for r in rows if r[0]]


@celery.task(name="app.tasks.exposure_digest.send_weekly_exposure_digests", bind=True, max_retries=1)
def send_weekly_exposure_digests(self) -> dict:
    """Send the weekly exposure digest to every tenant with noteworthy change."""
    stats = {"status": "completed", "tenants": 0, "sent": 0, "skipped": 0}
    if not settings.weekly_digest_enabled:
        stats["status"] = "disabled"
        return stats

    from app.models.database import Tenant
    from app.services.email_service import send_email
    from app.services.exposure_digest import build_digest, render_digest_html

    mark_cross_tenant()  # this beat task legitimately spans all tenants
    db = SessionLocal()
    try:
        with allow_cross_tenant():
            tenants = db.query(Tenant).all()
        for tenant in tenants:
            stats["tenants"] += 1
            with tenant_scope(tenant.id):
                digest = build_digest(db, tenant.id)
                recipients = _tenant_recipients(db, tenant.id)
            if not digest["has_noteworthy"] or not recipients:
                stats["skipped"] += 1
                continue
            subject = f"[{tenant.name}] Weekly exposure digest"
            html = render_digest_html(digest, tenant.name)
            if send_email(recipients, subject, html):
                stats["sent"] += 1
            else:
                stats["skipped"] += 1
    except Exception as exc:
        logger.error("weekly exposure digest failed: %s", exc, exc_info=True)
        stats["status"] = "error"
    finally:
        db.close()
    return stats
