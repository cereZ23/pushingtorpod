"""
Alert policy evaluation task.

Evaluates tenant alert policies against recent findings after scan completion.
Unlike the event-driven approach in diff_alert.py (which passes lightweight
event dicts), this task queries actual Finding/Asset rows from the database
so that policy conditions (severity threshold, asset type, source filter)
can be matched accurately.

Called as the final step after Phase 12 completes, or on-demand.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.database import Asset, Finding, FindingSeverity, FindingStatus
from app.models.risk import Alert, AlertPolicy, AlertStatus
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@celery.task(
    name="app.tasks.alert_evaluation.evaluate_alert_policies",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def evaluate_alert_policies(
    self,
    tenant_id: int,
    scan_run_id: int | None = None,
):
    """Evaluate alert policies against recent findings for a tenant.

    Queries all active alert policies for the tenant, fetches findings
    discovered in the last hour (or tied to the given scan run), and
    checks each policy's conditions against those findings.  Matching
    policies produce :class:`Alert` records and dispatch notifications
    through the configured channels.

    Args:
        tenant_id: Tenant whose policies should be evaluated.
        scan_run_id: Optional scan run that just completed.  Currently
            used only for logging context; finding selection is
            time-based to avoid coupling to scan-run bookkeeping.

    Returns:
        Dict with ``evaluated`` (number of policies checked) and
        ``triggered`` (number of policies that produced at least one
        alert).
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # -----------------------------------------------------------------
        # 1. Load active policies
        # -----------------------------------------------------------------
        policies = (
            db.query(AlertPolicy)
            .filter(
                AlertPolicy.tenant_id == tenant_id,
                AlertPolicy.enabled.is_(True),
            )
            .all()
        )

        if not policies:
            tenant_logger.info("No active alert policies, skipping evaluation")
            return {"evaluated": 0, "triggered": 0}

        # -----------------------------------------------------------------
        # 2. Fetch recent findings (first_seen within the last hour)
        # -----------------------------------------------------------------
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        recent_findings = (
            db.query(Finding)
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.first_seen >= cutoff,
                Finding.status == FindingStatus.OPEN,
            )
            .all()
        )

        if not recent_findings:
            tenant_logger.info(
                "No recent findings for tenant %d (cutoff=%s), nothing to evaluate",
                tenant_id,
                cutoff.isoformat(),
            )
            return {"evaluated": len(policies), "triggered": 0}

        # Pre-load assets for the findings to avoid N+1 queries.
        # SQLAlchemy lazy-loads by default; eagerly accessing the
        # relationship here is acceptable because the result set is
        # bounded by the 1-hour window.
        asset_cache: dict[int, Asset] = {}
        for finding in recent_findings:
            if finding.asset_id not in asset_cache:
                asset_cache[finding.asset_id] = finding.asset

        # -----------------------------------------------------------------
        # 3. Evaluate each policy
        # -----------------------------------------------------------------
        triggered = 0
        total_alerts = 0

        for policy in policies:
            matching = _evaluate_policy(policy, recent_findings, asset_cache)
            if not matching:
                continue

            triggered += 1
            alerts_created = _create_and_send_alerts(
                db,
                policy,
                matching,
                tenant_id,
                tenant_logger,
            )
            total_alerts += alerts_created

        db.commit()

        tenant_logger.info(
            "Alert evaluation complete: %d policies, %d triggered, %d alerts created, %d findings checked",
            len(policies),
            triggered,
            total_alerts,
            len(recent_findings),
        )

        return {
            "evaluated": len(policies),
            "triggered": triggered,
            "alerts_created": total_alerts,
            "findings_checked": len(recent_findings),
        }

    except Exception as exc:
        tenant_logger.error(
            "Alert evaluation failed for tenant %d: %s",
            tenant_id,
            exc,
            exc_info=True,
        )
        db.rollback()
        raise self.retry(exc=exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Policy condition matching
# ---------------------------------------------------------------------------


def _evaluate_policy(
    policy: AlertPolicy,
    findings: list[Finding],
    asset_cache: dict[int, Asset],
) -> list[Finding]:
    """Return findings that match *all* conditions of a policy.

    Supported ``conditions`` keys (stored as JSON on the policy):

    * ``severity`` -- minimum severity string (e.g. ``"high"``).
      A finding matches when its severity rank is >= the threshold.
    * ``asset_types`` -- list of asset-type strings (e.g.
      ``["subdomain", "ip"]``).  A finding matches when its parent
      asset type is in the list.
    * ``sources`` -- list of finding source strings (e.g.
      ``["nuclei", "misconfig"]``).  A finding matches when its
      ``source`` field is in the list.
    * ``template_ids`` -- list of Nuclei template ID prefixes.  A
      finding matches when its ``template_id`` starts with any of the
      given prefixes (supports glob-style trailing ``*``).

    Only ``finding_new`` events are emitted; policies whose
    ``event_types`` list does not contain ``"finding_new"`` are
    skipped entirely.
    """
    # This task only generates "finding_new" events.
    event_types = policy.event_types or []
    if "finding_new" not in event_types:
        return []

    conditions = policy.conditions or {}
    min_severity = conditions.get("severity", "info")
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    asset_types: list[str] | None = conditions.get("asset_types")
    sources: list[str] | None = conditions.get("sources")
    template_ids: list[str] | None = conditions.get("template_ids")

    matching: list[Finding] = []

    for finding in findings:
        # -- Severity gate --
        sev_value = finding.severity.value if isinstance(finding.severity, FindingSeverity) else str(finding.severity)
        if SEVERITY_RANK.get(sev_value, 0) < min_rank:
            continue

        # -- Asset type filter --
        if asset_types:
            asset = asset_cache.get(finding.asset_id)
            if asset:
                asset_type_str = asset.type.value if hasattr(asset.type, "value") else str(asset.type)
                if asset_type_str not in asset_types:
                    continue

        # -- Source filter --
        if sources and finding.source not in sources:
            continue

        # -- Template ID prefix filter --
        if template_ids:
            tid = finding.template_id or ""
            if not any(tid.startswith(prefix.rstrip("*")) for prefix in template_ids):
                continue

        matching.append(finding)

    return matching


# ---------------------------------------------------------------------------
# Alert creation & channel delivery
# ---------------------------------------------------------------------------


def _create_and_send_alerts(
    db,
    policy: AlertPolicy,
    matching_findings: list[Finding],
    tenant_id: int,
    tenant_logger: TenantLoggerAdapter,
) -> int:
    """Create Alert records and dispatch notifications.

    Respects per-policy cooldown windows and the global per-run volume
    cap (``settings.alert_max_per_run``).  When ``digest_mode`` is
    enabled on the policy a single summary alert is created instead of
    one per finding.

    Returns the number of alerts created.
    """
    alerts_created = 0
    now = datetime.now(timezone.utc)

    if policy.digest_mode:
        # Digest: one summary alert for the batch
        if _is_policy_in_cooldown(db, tenant_id, policy.id, policy.cooldown_minutes):
            return 0

        summary_lines = []
        for f in matching_findings[:20]:
            sev = f.severity.value if isinstance(f.severity, FindingSeverity) else str(f.severity)
            summary_lines.append(f"[{sev.upper()}] {f.name}")

        body = "\n".join(summary_lines)
        if len(matching_findings) > 20:
            body += f"\n... and {len(matching_findings) - 20} more"

        alert = Alert(
            tenant_id=tenant_id,
            policy_id=policy.id,
            event_type="finding_new",
            severity=_highest_severity(matching_findings),
            title=f"{policy.name}: {len(matching_findings)} finding(s) matched",
            body=body,
            status=AlertStatus.PENDING,
        )
        db.add(alert)
        db.flush()

        channels = _deliver_to_channels(policy, alert, tenant_logger)
        alert.channels_sent = channels
        alert.status = AlertStatus.SENT if channels else AlertStatus.PENDING
        alert.sent_at = now if channels else None
        alerts_created = 1

    else:
        # Individual alerts per finding (with volume cap)
        for finding in matching_findings:
            if alerts_created >= settings.alert_max_per_run:
                tenant_logger.warning(
                    "Alert volume cap (%d) reached for policy '%s'",
                    settings.alert_max_per_run,
                    policy.name,
                )
                break

            if _is_finding_in_cooldown(
                db,
                tenant_id,
                policy.id,
                finding.id,
                policy.cooldown_minutes,
            ):
                continue

            sev = finding.severity.value if isinstance(finding.severity, FindingSeverity) else str(finding.severity)
            asset = finding.asset

            alert = Alert(
                tenant_id=tenant_id,
                policy_id=policy.id,
                event_type="finding_new",
                severity=sev,
                title=f"New {sev.title()} Finding: {finding.name}",
                body=(
                    f"Asset: {asset.identifier if asset else 'N/A'}\n"
                    f"Template: {finding.template_id or 'N/A'}\n"
                    f"CVE: {finding.cve_id or 'N/A'}\n"
                    f"Source: {finding.source or 'N/A'}"
                ),
                related_asset_id=finding.asset_id,
                related_finding_id=finding.id,
                status=AlertStatus.PENDING,
            )
            db.add(alert)
            db.flush()

            channels = _deliver_to_channels(policy, alert, tenant_logger)
            alert.channels_sent = channels
            alert.status = AlertStatus.SENT if channels else AlertStatus.PENDING
            alert.sent_at = now if channels else None
            alerts_created += 1

    return alerts_created


# ---------------------------------------------------------------------------
# Cooldown checks
# ---------------------------------------------------------------------------


def _is_policy_in_cooldown(
    db,
    tenant_id: int,
    policy_id: int,
    cooldown_minutes: int,
) -> bool:
    """Return True if the policy fired within its cooldown window."""
    if cooldown_minutes <= 0:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
    return (
        db.query(Alert.id)
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.policy_id == policy_id,
            Alert.created_at >= cutoff,
        )
        .first()
        is not None
    )


def _is_finding_in_cooldown(
    db,
    tenant_id: int,
    policy_id: int,
    finding_id: int,
    cooldown_minutes: int,
) -> bool:
    """Return True if this specific finding already triggered an alert."""
    if cooldown_minutes <= 0:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
    return (
        db.query(Alert.id)
        .filter(
            Alert.tenant_id == tenant_id,
            Alert.policy_id == policy_id,
            Alert.related_finding_id == finding_id,
            Alert.created_at >= cutoff,
        )
        .first()
        is not None
    )


# ---------------------------------------------------------------------------
# Channel delivery
# ---------------------------------------------------------------------------


def _deliver_to_channels(
    policy: AlertPolicy,
    alert: Alert,
    tenant_logger: TenantLoggerAdapter,
) -> list[str]:
    """Send alert through all channels configured on the policy.

    Delegates to the existing channel helpers in
    :mod:`app.tasks.alerting` to avoid duplicating Slack/email/webhook
    logic.

    Returns a list of channel type strings that succeeded.
    """
    channels_sent: list[str] = []

    for channel_config in policy.channels or []:
        channel_type = channel_config.get("type", "")
        try:
            _send_via_channel(channel_config, alert, tenant_logger)
            channels_sent.append(channel_type)
        except Exception:
            tenant_logger.exception(
                "Channel delivery failed for policy '%s' (%s)",
                policy.name,
                channel_type,
            )

    return channels_sent


def _send_via_channel(
    channel_config: dict,
    alert: Alert,
    tenant_logger: TenantLoggerAdapter,
) -> None:
    """Dispatch an alert through a single channel.

    Supported types: ``slack``, ``email``, ``webhook``, ``teams``, ``pagerduty``.
    """
    channel_type = channel_config.get("type", "")

    if channel_type == "slack":
        webhook_url = channel_config.get("webhook_url") or settings.slack_webhook_url
        if webhook_url:
            _send_slack_message(webhook_url, alert)

    elif channel_type == "email":
        recipient = channel_config.get("to")
        if recipient:
            _send_email_notification(recipient, alert)

    elif channel_type == "webhook":
        url = channel_config.get("webhook_url") or channel_config.get("url") or settings.webhook_url
        if url:
            _send_webhook_message(url, alert)

    elif channel_type == "teams":
        webhook_url = channel_config.get("webhook_url")
        if webhook_url:
            _send_teams_message(webhook_url, alert)

    elif channel_type == "pagerduty":
        routing_key = channel_config.get("routing_key")
        if routing_key:
            _send_pagerduty_event(routing_key, alert)

    else:
        tenant_logger.warning("Unknown channel type '%s', skipping", channel_type)


def _send_slack_message(webhook_url: str, alert: Alert) -> None:
    """Post an alert to a Slack incoming webhook."""
    import httpx

    color_map = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFAA00",
        "low": "#0066FF",
        "info": "#808080",
    }

    payload = {
        "attachments": [
            {
                "color": color_map.get(alert.severity, "#808080"),
                "title": alert.title,
                "text": alert.body or "",
                "footer": "EASM Platform",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }

    with httpx.Client(timeout=10) as client:
        response = client.post(webhook_url, json=payload)
        response.raise_for_status()


def _send_email_notification(recipient: str, alert: Alert) -> None:
    """Send an alert via the shared email service."""
    from app.services.email_service import send_email

    subject = f"[EASM Alert] {alert.title}"
    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1e293b;">{alert.title}</h2>
        <p style="color: #475569; white-space: pre-line;">{alert.body or ""}</p>
        <hr style="border: none; border-top: 1px solid #e2e8f0;">
        <p style="color: #94a3b8; font-size: 12px;">
            Severity: {alert.severity} | Event: {alert.event_type} | EASM Platform
        </p>
    </div>
    """
    text = f"{alert.title}\n\n{alert.body or ''}\n\nSeverity: {alert.severity}"

    send_email([recipient], subject, html, text)


def _send_webhook_message(url: str, alert: Alert) -> None:
    """POST alert payload to a generic webhook URL with optional HMAC."""
    import hashlib
    import hmac
    import json

    import httpx

    payload = {
        "event_type": alert.event_type,
        "severity": alert.severity,
        "title": alert.title,
        "body": alert.body,
        "policy_id": alert.policy_id,
        "related_asset_id": alert.related_asset_id,
        "related_finding_id": alert.related_finding_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    headers: dict[str, str] = {"Content-Type": "application/json"}

    if settings.webhook_secret:
        body_bytes = json.dumps(payload).encode()
        signature = hmac.new(
            settings.webhook_secret.encode(),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()
        headers["X-EASM-Signature"] = f"sha256={signature}"

    with httpx.Client(timeout=10) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()


def _send_teams_message(webhook_url: str, alert: Alert) -> None:
    """Post an alert to a Microsoft Teams incoming webhook using Adaptive Card."""
    import httpx

    color_map = {
        "critical": "attention",
        "high": "warning",
        "medium": "warning",
        "low": "accent",
        "info": "default",
    }

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "medium",
                            "weight": "bolder",
                            "text": alert.title,
                            "style": color_map.get(alert.severity, "default"),
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.body or "",
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": (alert.severity or "info").upper()},
                                {"title": "Event", "value": alert.event_type or ""},
                                {"title": "Source", "value": "EASM Platform"},
                            ],
                        },
                    ],
                },
            }
        ],
    }

    with httpx.Client(timeout=10) as client:
        response = client.post(webhook_url, json=card)
        response.raise_for_status()


def _send_pagerduty_event(routing_key: str, alert: Alert) -> None:
    """Create a PagerDuty incident via Events API v2."""
    import httpx

    severity_map = {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
        "info": "info",
    }

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert.title,
            "source": "easm-platform",
            "severity": severity_map.get(alert.severity, "info"),
            "component": "alert-evaluation",
            "custom_details": {
                "body": alert.body or "",
                "event_type": alert.event_type,
                "policy_id": alert.policy_id,
                "related_asset_id": alert.related_asset_id,
                "related_finding_id": alert.related_finding_id,
            },
        },
    }

    with httpx.Client(timeout=10) as client:
        response = client.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
        )
        response.raise_for_status()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _highest_severity(findings: list[Finding]) -> str:
    """Return the highest severity string across a list of findings."""
    max_rank = 0
    max_sev = "info"
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, FindingSeverity) else str(f.severity)
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = sev
    return max_sev
