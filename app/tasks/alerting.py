"""
Alerting tasks for EASM platform.

Implements alert evaluation, channel delivery (Slack, Email, Webhook),
cooldown dedup, and volume capping.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.risk import Alert, AlertStatus, AlertPolicy
from app.models.database import Asset, Finding, FindingSeverity
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)


@celery.task(name='app.tasks.alerting.send_critical_alerts')
def send_critical_alerts(tenant_id: int):
    """Send alerts for new critical findings discovered in the last hour."""
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {'tenant_id': tenant_id})

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        critical_findings = db.query(Finding).join(Asset).filter(
            Asset.tenant_id == tenant_id,
            Finding.severity == FindingSeverity.CRITICAL,
            Finding.first_seen >= cutoff,
            Finding.status == 'open'
        ).all()

        if not critical_findings:
            return {'alerts_sent': 0}

        alerts_sent = 0
        for finding in critical_findings:
            asset = finding.asset

            # Check cooldown - don't re-alert for same finding
            existing_alert = db.query(Alert).filter(
                Alert.tenant_id == tenant_id,
                Alert.related_finding_id == finding.id,
                Alert.created_at >= datetime.now(timezone.utc) - timedelta(minutes=settings.alert_cooldown_minutes)
            ).first()

            if existing_alert:
                continue

            # Create alert record
            alert = Alert(
                tenant_id=tenant_id,
                event_type='finding_new',
                severity='critical',
                title=f"Critical Finding: {finding.name}",
                body=f"Asset: {asset.identifier}\nTemplate: {finding.template_id}\nCVE: {finding.cve_id or 'N/A'}",
                related_asset_id=asset.id,
                related_finding_id=finding.id,
                status=AlertStatus.PENDING,
            )
            db.add(alert)
            db.flush()

            # Send via configured channels
            channels_sent = []

            if settings.slack_webhook_url:
                try:
                    _send_slack_alert(alert, asset, finding)
                    channels_sent.append('slack')
                except Exception as e:
                    tenant_logger.error(f"Slack alert failed: {e}")

            if settings.smtp_host and settings.smtp_from:
                try:
                    _send_email_alert(alert, asset, finding, tenant_logger)
                    channels_sent.append('email')
                except Exception as e:
                    tenant_logger.error(f"Email alert failed: {e}")

            if settings.webhook_url:
                try:
                    _send_webhook_alert(alert, asset, finding)
                    channels_sent.append('webhook')
                except Exception as e:
                    tenant_logger.error(f"Webhook alert failed: {e}")

            alert.channels_sent = channels_sent
            alert.status = AlertStatus.SENT if channels_sent else AlertStatus.PENDING
            alert.sent_at = datetime.now(timezone.utc) if channels_sent else None
            alerts_sent += 1

        db.commit()
        tenant_logger.info(f"Sent {alerts_sent} critical alerts")
        return {'alerts_sent': alerts_sent}

    except Exception as e:
        tenant_logger.error(f"Critical alerts error: {e}", exc_info=True)
        db.rollback()
        return {'error': str(e), 'alerts_sent': 0}
    finally:
        db.close()


@celery.task(name='app.tasks.alerting.send_new_asset_alerts')
def send_new_asset_alerts(tenant_id: int):
    """Send alerts for new assets discovered in the last hour."""
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {'tenant_id': tenant_id})

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        new_assets = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.first_seen >= cutoff,
            Asset.is_active == True
        ).all()

        if not new_assets:
            return {'alerts_sent': 0}

        # Volume cap
        if len(new_assets) > settings.alert_max_per_run:
            tenant_logger.warning(
                f"New asset count ({len(new_assets)}) exceeds cap ({settings.alert_max_per_run}), "
                f"sending summary alert"
            )
            alert = Alert(
                tenant_id=tenant_id,
                event_type='asset_new',
                severity='info',
                title=f"{len(new_assets)} New Assets Discovered",
                body=f"Digest: {len(new_assets)} new assets found. Check dashboard for details.",
                status=AlertStatus.PENDING,
            )
            db.add(alert)
            db.commit()

            channels = _send_to_all_channels(alert, tenant_logger)
            alert.channels_sent = channels
            alert.status = AlertStatus.SENT if channels else AlertStatus.PENDING
            alert.sent_at = datetime.now(timezone.utc) if channels else None
            db.commit()

            return {'alerts_sent': 1, 'assets_count': len(new_assets)}

        alerts_sent = 0
        for asset in new_assets:
            alert = Alert(
                tenant_id=tenant_id,
                event_type='asset_new',
                severity='info',
                title=f"New Asset: {asset.identifier}",
                body=f"Type: {asset.type.value}\nIdentifier: {asset.identifier}",
                related_asset_id=asset.id,
                status=AlertStatus.PENDING,
            )
            db.add(alert)
            alerts_sent += 1

        db.commit()
        tenant_logger.info(f"Created {alerts_sent} new asset alerts")
        return {'alerts_sent': alerts_sent}

    except Exception as e:
        tenant_logger.error(f"New asset alerts error: {e}", exc_info=True)
        db.rollback()
        return {'error': str(e), 'alerts_sent': 0}
    finally:
        db.close()


@celery.task(name='app.tasks.alerting.evaluate_alert_policies')
def evaluate_alert_policies(tenant_id: int, events: list):
    """
    Evaluate alert policies against a list of events.

    Events format: [{"type": "finding_new", "severity": "critical", "asset_id": 1, "finding_id": 2}, ...]
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {'tenant_id': tenant_id})

    try:
        # Get active policies for tenant
        policies = db.query(AlertPolicy).filter(
            AlertPolicy.tenant_id == tenant_id,
            AlertPolicy.enabled == True
        ).all()

        if not policies:
            return {'alerts_created': 0}

        alerts_created = 0

        for event in events:
            if alerts_created >= settings.alert_max_per_run:
                tenant_logger.warning(f"Alert volume cap reached ({settings.alert_max_per_run})")
                break

            for policy in policies:
                if not _event_matches_policy(event, policy):
                    continue

                # Check cooldown
                if _is_in_cooldown(db, tenant_id, policy.id, event):
                    continue

                # Create alert
                alert = Alert(
                    tenant_id=tenant_id,
                    policy_id=policy.id,
                    event_type=event.get('type', 'unknown'),
                    severity=event.get('severity', 'info'),
                    title=_build_alert_title(event),
                    body=_build_alert_body(event),
                    related_asset_id=event.get('asset_id'),
                    related_finding_id=event.get('finding_id'),
                    status=AlertStatus.PENDING,
                )
                db.add(alert)
                db.flush()

                # Send via policy channels
                channels = []
                for channel_config in (policy.channels or []):
                    try:
                        _send_via_channel(channel_config, alert, tenant_logger)
                        channels.append(channel_config.get('type', 'unknown'))
                    except Exception as e:
                        tenant_logger.error(f"Channel delivery failed: {e}")

                alert.channels_sent = channels
                alert.status = AlertStatus.SENT if channels else AlertStatus.PENDING
                alert.sent_at = datetime.now(timezone.utc) if channels else None
                alerts_created += 1

        db.commit()
        return {'alerts_created': alerts_created}

    except Exception as e:
        tenant_logger.error(f"Policy evaluation error: {e}", exc_info=True)
        db.rollback()
        return {'error': str(e)}
    finally:
        db.close()


def _event_matches_policy(event: dict, policy: AlertPolicy) -> bool:
    """Check if an event matches a policy's event_types and conditions."""
    event_type = event.get('type', '')

    # Check event type match
    if event_type not in (policy.event_types or []):
        return False

    # Check conditions
    conditions = policy.conditions or {}

    if 'severity' in conditions:
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        event_sev = severity_order.get(event.get('severity', ''), 0)
        required_sev = severity_order.get(conditions['severity'], 0)
        if event_sev < required_sev:
            return False

    if 'control_id' in conditions:
        pattern = conditions['control_id']
        control = event.get('control_id', '')
        if pattern.endswith('*'):
            if not control.startswith(pattern[:-1]):
                return False
        elif control != pattern:
            return False

    return True


def _is_in_cooldown(db, tenant_id: int, policy_id: int, event: dict) -> bool:
    """Check if a similar alert was sent recently (cooldown dedup)."""
    policy = db.query(AlertPolicy).filter(AlertPolicy.id == policy_id).first()
    cooldown = policy.cooldown_minutes if policy else settings.alert_cooldown_minutes

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown)

    existing = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.policy_id == policy_id,
        Alert.event_type == event.get('type'),
        Alert.related_asset_id == event.get('asset_id'),
        Alert.created_at >= cutoff
    ).first()

    return existing is not None


def _build_alert_title(event: dict) -> str:
    """Build alert title from event data."""
    event_type = event.get('type', 'unknown')
    if event_type == 'finding_new':
        return f"New {event.get('severity', '').title()} Finding: {event.get('name', 'Unknown')}"
    elif event_type == 'asset_new':
        return f"New Asset Discovered: {event.get('identifier', 'Unknown')}"
    elif event_type == 'cert_expiring':
        return f"Certificate Expiring: {event.get('identifier', 'Unknown')}"
    elif event_type == 'score_changed':
        return f"Risk Score Changed: {event.get('delta', 0):+.1f} points"
    return f"Alert: {event_type}"


def _build_alert_body(event: dict) -> str:
    """Build alert body from event data."""
    parts = []
    for key, value in event.items():
        if key not in ('type',) and value is not None:
            parts.append(f"{key}: {value}")
    return '\n'.join(parts)


def _send_to_all_channels(alert: Alert, tenant_logger) -> list:
    """Send alert to all configured channels."""
    channels = []
    if settings.slack_webhook_url:
        try:
            _send_slack_alert(alert)
            channels.append('slack')
        except Exception as e:
            tenant_logger.error(f"Slack failed: {e}")
    if settings.webhook_url:
        try:
            _send_webhook_alert(alert)
            channels.append('webhook')
        except Exception as e:
            tenant_logger.error(f"Webhook failed: {e}")
    return channels


def _send_via_channel(channel_config: dict, alert: Alert, tenant_logger):
    """Send alert via a specific channel configuration."""
    channel_type = channel_config.get('type', '')

    if channel_type == 'slack':
        webhook = channel_config.get('webhook_url') or settings.slack_webhook_url
        if webhook:
            _send_slack_message(webhook, alert.title, alert.body, alert.severity)

    elif channel_type == 'email':
        _send_email_alert(alert, tenant_logger=tenant_logger)

    elif channel_type == 'webhook':
        url = channel_config.get('url') or settings.webhook_url
        if url:
            _send_webhook_message(url, alert)


def _send_slack_alert(alert: Alert, asset=None, finding=None):
    """Send alert to Slack via webhook."""
    if not settings.slack_webhook_url:
        return
    _send_slack_message(settings.slack_webhook_url, alert.title, alert.body, alert.severity)


def _send_slack_message(webhook_url: str, title: str, body: str, severity: str = 'info'):
    """Send a Slack message via incoming webhook."""
    color_map = {
        'critical': '#FF0000',
        'high': '#FF6600',
        'medium': '#FFAA00',
        'low': '#0066FF',
        'info': '#808080',
    }

    payload = {
        "attachments": [{
            "color": color_map.get(severity, '#808080'),
            "title": title,
            "text": body,
            "footer": "EASM Platform",
            "ts": int(datetime.now(timezone.utc).timestamp())
        }]
    }

    with httpx.Client(timeout=10) as client:
        response = client.post(webhook_url, json=payload)
        response.raise_for_status()


def _send_email_alert(alert: Alert, asset=None, finding=None, tenant_logger=None):
    """Send alert via SMTP email."""
    if not settings.smtp_host or not settings.smtp_from:
        return

    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(alert.body or '')
    msg['Subject'] = f"[EASM] {alert.title}"
    msg['From'] = settings.smtp_from
    msg['To'] = settings.smtp_from  # Send to self by default

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
        server.starttls()
        if settings.smtp_user and settings.smtp_password:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)


def _send_webhook_alert(alert: Alert, asset=None, finding=None):
    """Send alert to generic webhook."""
    if not settings.webhook_url:
        return
    _send_webhook_message(settings.webhook_url, alert)


def _send_webhook_message(url: str, alert: Alert):
    """Send alert payload to a webhook URL."""
    import hashlib
    import hmac

    payload = {
        'event_type': alert.event_type,
        'severity': alert.severity,
        'title': alert.title,
        'body': alert.body,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }

    headers = {'Content-Type': 'application/json'}

    # HMAC signing if webhook secret configured
    if settings.webhook_secret:
        body_bytes = json.dumps(payload).encode()
        signature = hmac.new(
            settings.webhook_secret.encode(),
            body_bytes,
            hashlib.sha256
        ).hexdigest()
        headers['X-EASM-Signature'] = f"sha256={signature}"

    with httpx.Client(timeout=10) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
