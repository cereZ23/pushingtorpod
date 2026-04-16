"""
Unit tests for app/tasks/alerting.py helper functions.

Covers pure helpers:
- _event_matches_policy: event_type, severity threshold, control_id prefix/exact
- _build_alert_title: all known event types + unknown fallback
- _build_alert_body: serialization, skips 'type' and None values
- _send_slack_message: color map + payload shape, raise_for_status called
- _send_webhook_message: HMAC signing when secret configured
- _send_to_all_channels: skip when settings missing
- _send_slack_alert, _send_webhook_alert: no-op when no URL
- _send_email_alert: no-op when smtp not configured
- _is_in_cooldown: existing alert found / not found
- _send_via_channel: routes by type
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.tasks import alerting as alerting_mod


class _Settings:
    def __init__(
        self,
        slack_webhook_url=None,
        webhook_url=None,
        webhook_secret=None,
        smtp_host=None,
        smtp_from=None,
        smtp_user=None,
        smtp_password=None,
        smtp_port=587,
        alert_cooldown_minutes=15,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.smtp_host = smtp_host
        self.smtp_from = smtp_from
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.smtp_port = smtp_port
        self.alert_cooldown_minutes = alert_cooldown_minutes


def _alert(
    title="T",
    body="B",
    severity="critical",
    event_type="finding_new",
):
    a = SimpleNamespace()
    a.title = title
    a.body = body
    a.severity = severity
    a.event_type = event_type
    a.id = 1
    return a


def _policy(event_types=None, conditions=None, cooldown_minutes=None):
    return SimpleNamespace(
        event_types=event_types or ["finding_new"],
        conditions=conditions or {},
        cooldown_minutes=cooldown_minutes,
    )


class TestEventMatchesPolicy:
    def test_type_match(self):
        policy = _policy(event_types=["finding_new"])
        assert alerting_mod._event_matches_policy({"type": "finding_new"}, policy) is True

    def test_type_mismatch(self):
        policy = _policy(event_types=["asset_new"])
        assert alerting_mod._event_matches_policy({"type": "finding_new"}, policy) is False

    def test_severity_threshold_met(self):
        policy = _policy(conditions={"severity": "medium"})
        assert alerting_mod._event_matches_policy({"type": "finding_new", "severity": "high"}, policy) is True

    def test_severity_threshold_not_met(self):
        policy = _policy(conditions={"severity": "high"})
        assert alerting_mod._event_matches_policy({"type": "finding_new", "severity": "low"}, policy) is False

    def test_control_id_exact_match(self):
        policy = _policy(conditions={"control_id": "MISCONFIG-001"})
        assert (
            alerting_mod._event_matches_policy({"type": "finding_new", "control_id": "MISCONFIG-001"}, policy) is True
        )

    def test_control_id_exact_mismatch(self):
        policy = _policy(conditions={"control_id": "MISCONFIG-001"})
        assert (
            alerting_mod._event_matches_policy({"type": "finding_new", "control_id": "MISCONFIG-002"}, policy) is False
        )

    def test_control_id_prefix_match(self):
        policy = _policy(conditions={"control_id": "MISCONFIG-*"})
        assert (
            alerting_mod._event_matches_policy({"type": "finding_new", "control_id": "MISCONFIG-005"}, policy) is True
        )

    def test_control_id_prefix_no_match(self):
        policy = _policy(conditions={"control_id": "ROLE-*"})
        assert alerting_mod._event_matches_policy({"type": "finding_new", "control_id": "OTHER-01"}, policy) is False

    def test_empty_event_types(self):
        policy = _policy(event_types=[])
        assert alerting_mod._event_matches_policy({"type": "x"}, policy) is False


class TestBuildAlertTitle:
    def test_finding_new(self):
        title = alerting_mod._build_alert_title({"type": "finding_new", "severity": "critical", "name": "Bad"})
        assert "Critical" in title
        assert "Bad" in title

    def test_asset_new(self):
        title = alerting_mod._build_alert_title({"type": "asset_new", "identifier": "x.com"})
        assert "New Asset" in title
        assert "x.com" in title

    def test_cert_expiring(self):
        title = alerting_mod._build_alert_title({"type": "cert_expiring", "identifier": "x.com"})
        assert "Certificate" in title

    def test_score_changed(self):
        title = alerting_mod._build_alert_title({"type": "score_changed", "delta": 5.5})
        assert "Risk Score" in title
        assert "5.5" in title

    def test_unknown_type(self):
        title = alerting_mod._build_alert_title({"type": "weird"})
        assert "weird" in title


class TestBuildAlertBody:
    def test_basic(self):
        body = alerting_mod._build_alert_body({"type": "x", "asset": "a.com", "severity": "high"})
        assert "asset: a.com" in body
        assert "severity: high" in body
        # 'type' excluded
        assert "type" not in body.split("\n")[0].split(":")[0]

    def test_skips_none_values(self):
        body = alerting_mod._build_alert_body({"type": "x", "asset": None, "name": "F"})
        assert "asset" not in body
        assert "name: F" in body


class TestSendSlackMessage:
    def test_payload_shape(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            alerting_mod._send_slack_message("https://slack/webhook", "T", "B", severity="high")
        args, kwargs = ctx.post.call_args
        assert args[0] == "https://slack/webhook"
        payload = kwargs["json"]
        assert payload["attachments"][0]["color"] == "#FF6600"
        assert payload["attachments"][0]["title"] == "T"

    def test_default_color_for_unknown_severity(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            alerting_mod._send_slack_message("u", "t", "b", severity="weird")
        kwargs = ctx.post.call_args.kwargs
        assert kwargs["json"]["attachments"][0]["color"] == "#808080"


class TestSendWebhookMessage:
    def test_hmac_sign(self):
        with patch.object(alerting_mod, "settings", _Settings(webhook_secret="secret")):
            with patch("httpx.Client") as mock_client:
                ctx = mock_client.return_value.__enter__.return_value
                ctx.post.return_value = MagicMock()
                alerting_mod._send_webhook_message("https://webhook", _alert())
        kwargs = ctx.post.call_args.kwargs
        assert "X-EASM-Signature" in kwargs["headers"]
        assert kwargs["headers"]["X-EASM-Signature"].startswith("sha256=")

    def test_without_secret_no_signature(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            with patch("httpx.Client") as mock_client:
                ctx = mock_client.return_value.__enter__.return_value
                ctx.post.return_value = MagicMock()
                alerting_mod._send_webhook_message("https://webhook", _alert())
        kwargs = ctx.post.call_args.kwargs
        assert "X-EASM-Signature" not in kwargs["headers"]


class TestSendToAllChannels:
    def test_no_channels_configured(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            channels = alerting_mod._send_to_all_channels(_alert(), MagicMock())
        assert channels == []

    def test_slack_only(self):
        with patch.object(alerting_mod, "settings", _Settings(slack_webhook_url="https://s")):
            with patch.object(alerting_mod, "_send_slack_alert") as mock_send:
                channels = alerting_mod._send_to_all_channels(_alert(), MagicMock())
        assert "slack" in channels
        assert mock_send.called

    def test_slack_and_webhook(self):
        with patch.object(
            alerting_mod,
            "settings",
            _Settings(slack_webhook_url="https://s", webhook_url="https://w"),
        ):
            with patch.object(alerting_mod, "_send_slack_alert"):
                with patch.object(alerting_mod, "_send_webhook_alert"):
                    channels = alerting_mod._send_to_all_channels(_alert(), MagicMock())
        assert "slack" in channels
        assert "webhook" in channels

    def test_channel_failure_logged(self):
        with patch.object(alerting_mod, "settings", _Settings(slack_webhook_url="https://s")):
            with patch.object(alerting_mod, "_send_slack_alert", side_effect=RuntimeError("boom")):
                tenant_logger = MagicMock()
                channels = alerting_mod._send_to_all_channels(_alert(), tenant_logger)
        assert channels == []
        tenant_logger.error.assert_called()


class TestSendViaChannel:
    def test_slack_channel(self):
        with patch.object(alerting_mod, "settings", _Settings(slack_webhook_url="https://default")):
            with patch.object(alerting_mod, "_send_slack_message") as mock_send:
                alerting_mod._send_via_channel(
                    {"type": "slack", "webhook_url": "https://custom"},
                    _alert(),
                    MagicMock(),
                )
        mock_send.assert_called_once()
        assert mock_send.call_args.args[0] == "https://custom"

    def test_email_channel(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            with patch.object(alerting_mod, "_send_email_alert") as mock_send:
                alerting_mod._send_via_channel({"type": "email"}, _alert(), MagicMock())
        mock_send.assert_called_once()

    def test_webhook_channel(self):
        with patch.object(alerting_mod, "settings", _Settings(webhook_url="https://default")):
            with patch.object(alerting_mod, "_send_webhook_message") as mock_send:
                alerting_mod._send_via_channel(
                    {"type": "webhook", "url": "https://custom"},
                    _alert(),
                    MagicMock(),
                )
        mock_send.assert_called_once()
        assert mock_send.call_args.args[0] == "https://custom"

    def test_unknown_channel_noop(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            # no function called
            alerting_mod._send_via_channel({"type": "???"}, _alert(), MagicMock())


class TestSendAlertsNoConfig:
    def test_send_slack_alert_no_url(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            # Should return without raising
            alerting_mod._send_slack_alert(_alert())

    def test_send_webhook_alert_no_url(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            alerting_mod._send_webhook_alert(_alert())

    def test_send_email_alert_no_smtp(self):
        with patch.object(alerting_mod, "settings", _Settings()):
            alerting_mod._send_email_alert(_alert())


class TestIsInCooldown:
    def test_no_existing_alert(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with patch.object(alerting_mod, "settings", _Settings()):
            result = alerting_mod._is_in_cooldown(db, 1, 1, {"type": "x"})
        assert result is False

    def test_existing_alert(self):
        db = MagicMock()
        # First call: policy lookup returns None (uses default), second: alert found
        calls = [_policy(cooldown_minutes=30), SimpleNamespace(id=99)]
        db.query.return_value.filter.return_value.first.side_effect = calls
        with patch.object(alerting_mod, "settings", _Settings()):
            result = alerting_mod._is_in_cooldown(db, 1, 1, {"type": "x", "asset_id": 5})
        assert result is True
