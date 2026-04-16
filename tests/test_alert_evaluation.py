"""
Unit tests for app/tasks/alert_evaluation.py helper functions.

Covers:
- SEVERITY_RANK mapping
- _evaluate_policy: event_types gate, severity, asset_types, sources, template_ids
- _is_policy_in_cooldown / _is_finding_in_cooldown (cooldown<=0 fast-path, query result)
- _highest_severity
- _send_slack_message, _send_webhook_message, _send_teams_message, _send_pagerduty_event
  payload shape + raise_for_status
- _send_email_notification delegates to send_email
- _send_via_channel routes by type
- _deliver_to_channels handles failures gracefully
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.models.database import FindingSeverity
from app.tasks import alert_evaluation as ae


class _Settings:
    def __init__(
        self,
        slack_webhook_url=None,
        webhook_url=None,
        webhook_secret=None,
        alert_max_per_run=50,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.alert_max_per_run = alert_max_per_run


def _alert(
    title="T",
    body="B",
    severity="critical",
    event_type="finding_new",
    policy_id=1,
    related_asset_id=10,
    related_finding_id=20,
):
    return SimpleNamespace(
        title=title,
        body=body,
        severity=severity,
        event_type=event_type,
        policy_id=policy_id,
        related_asset_id=related_asset_id,
        related_finding_id=related_finding_id,
    )


def _finding(
    id_=1,
    asset_id=10,
    source="nuclei",
    template_id="tpl",
    severity=FindingSeverity.HIGH,
):
    return SimpleNamespace(
        id=id_,
        asset_id=asset_id,
        source=source,
        template_id=template_id,
        severity=severity,
        name="F",
        cve_id=None,
        asset=None,
    )


def _policy(
    event_types=None,
    conditions=None,
    digest_mode=False,
    channels=None,
    cooldown_minutes=0,
):
    return SimpleNamespace(
        id=1,
        name="P1",
        event_types=event_types or ["finding_new"],
        conditions=conditions or {},
        digest_mode=digest_mode,
        channels=channels or [],
        cooldown_minutes=cooldown_minutes,
    )


class TestSeverityRank:
    def test_ordering(self):
        assert (
            ae.SEVERITY_RANK["info"]
            < ae.SEVERITY_RANK["low"]
            < ae.SEVERITY_RANK["medium"]
            < ae.SEVERITY_RANK["high"]
            < ae.SEVERITY_RANK["critical"]
        )


class TestEvaluatePolicy:
    def test_event_type_not_finding_new(self):
        policy = _policy(event_types=["asset_new"])
        findings = [_finding()]
        assert ae._evaluate_policy(policy, findings, {}) == []

    def test_all_findings_match_empty_conditions(self):
        policy = _policy()
        findings = [_finding(severity=FindingSeverity.LOW)]
        assert len(ae._evaluate_policy(policy, findings, {})) == 1

    def test_severity_gate_filters(self):
        policy = _policy(conditions={"severity": "high"})
        findings = [
            _finding(id_=1, severity=FindingSeverity.LOW),
            _finding(id_=2, severity=FindingSeverity.HIGH),
            _finding(id_=3, severity=FindingSeverity.CRITICAL),
        ]
        result = ae._evaluate_policy(policy, findings, {})
        ids = {f.id for f in result}
        assert ids == {2, 3}

    def test_asset_type_filter(self):
        policy = _policy(conditions={"asset_types": ["ip"]})
        a = SimpleNamespace(type=SimpleNamespace(value="subdomain"))
        asset_cache = {1: a}
        findings = [_finding(id_=1, asset_id=1, severity=FindingSeverity.HIGH)]
        assert ae._evaluate_policy(policy, findings, asset_cache) == []

    def test_asset_type_filter_matches(self):
        policy = _policy(conditions={"asset_types": ["subdomain"]})
        a = SimpleNamespace(type=SimpleNamespace(value="subdomain"))
        asset_cache = {1: a}
        findings = [_finding(id_=1, asset_id=1, severity=FindingSeverity.HIGH)]
        result = ae._evaluate_policy(policy, findings, asset_cache)
        assert len(result) == 1

    def test_sources_filter(self):
        policy = _policy(conditions={"sources": ["nuclei"]})
        findings = [
            _finding(id_=1, source="nuclei"),
            _finding(id_=2, source="misconfig"),
        ]
        result = ae._evaluate_policy(policy, findings, {})
        assert {f.id for f in result} == {1}

    def test_template_ids_prefix(self):
        policy = _policy(conditions={"template_ids": ["CVE-2024*"]})
        findings = [
            _finding(id_=1, template_id="CVE-2024-001"),
            _finding(id_=2, template_id="CVE-2023-999"),
        ]
        result = ae._evaluate_policy(policy, findings, {})
        assert {f.id for f in result} == {1}

    def test_template_ids_empty_missing_tid(self):
        policy = _policy(conditions={"template_ids": ["CVE-*"]})
        findings = [_finding(id_=1, template_id=None)]
        assert ae._evaluate_policy(policy, findings, {}) == []


class TestCooldowns:
    def test_policy_cooldown_zero_short_circuits(self):
        db = MagicMock()
        assert ae._is_policy_in_cooldown(db, 1, 1, cooldown_minutes=0) is False
        db.query.assert_not_called()

    def test_policy_cooldown_with_existing_alert(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = (99,)
        assert ae._is_policy_in_cooldown(db, 1, 1, cooldown_minutes=30) is True

    def test_policy_cooldown_no_alert(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert ae._is_policy_in_cooldown(db, 1, 1, cooldown_minutes=30) is False

    def test_finding_cooldown_zero(self):
        db = MagicMock()
        assert ae._is_finding_in_cooldown(db, 1, 1, 5, cooldown_minutes=0) is False

    def test_finding_cooldown_with_alert(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = (77,)
        assert ae._is_finding_in_cooldown(db, 1, 1, 5, cooldown_minutes=15) is True


class TestHighestSeverity:
    def test_empty_list_returns_info(self):
        assert ae._highest_severity([]) == "info"

    def test_critical_wins(self):
        findings = [
            _finding(severity=FindingSeverity.LOW),
            _finding(severity=FindingSeverity.CRITICAL),
            _finding(severity=FindingSeverity.HIGH),
        ]
        assert ae._highest_severity(findings) == "critical"

    def test_all_info(self):
        findings = [_finding(severity=FindingSeverity.INFO)]
        assert ae._highest_severity(findings) == "info"


class TestSlackMessage:
    def test_slack_payload(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_slack_message("https://slack", _alert(severity="high"))
        kwargs = ctx.post.call_args.kwargs
        assert kwargs["json"]["attachments"][0]["color"] == "#FF6600"

    def test_slack_default_color(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_slack_message("u", _alert(severity="???"))
        kwargs = ctx.post.call_args.kwargs
        assert kwargs["json"]["attachments"][0]["color"] == "#808080"


class TestWebhookMessage:
    def test_hmac_signed(self):
        with patch.object(ae, "settings", _Settings(webhook_secret="SECR")):
            with patch("httpx.Client") as mock_client:
                ctx = mock_client.return_value.__enter__.return_value
                ctx.post.return_value = MagicMock()
                ae._send_webhook_message("https://x", _alert())
        kwargs = ctx.post.call_args.kwargs
        assert "X-EASM-Signature" in kwargs["headers"]

    def test_no_secret_no_signature(self):
        with patch.object(ae, "settings", _Settings()):
            with patch("httpx.Client") as mock_client:
                ctx = mock_client.return_value.__enter__.return_value
                ctx.post.return_value = MagicMock()
                ae._send_webhook_message("https://x", _alert())
        kwargs = ctx.post.call_args.kwargs
        assert "X-EASM-Signature" not in kwargs["headers"]


class TestTeamsMessage:
    def test_teams_adaptive_card(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_teams_message("https://teams", _alert(severity="critical"))
        kwargs = ctx.post.call_args.kwargs
        card = kwargs["json"]
        assert card["type"] == "message"
        # Severity mapped to "attention" for critical
        text_block = card["attachments"][0]["content"]["body"][0]
        assert text_block["style"] == "attention"

    def test_teams_default_style(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_teams_message("u", _alert(severity="unknown"))
        text_block = ctx.post.call_args.kwargs["json"]["attachments"][0]["content"]["body"][0]
        assert text_block["style"] == "default"


class TestPagerDuty:
    def test_pd_payload(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_pagerduty_event("KEY", _alert(severity="high"))
        args, kwargs = ctx.post.call_args
        assert args[0] == "https://events.pagerduty.com/v2/enqueue"
        assert kwargs["json"]["routing_key"] == "KEY"
        assert kwargs["json"]["payload"]["severity"] == "error"

    def test_pd_severity_fallback(self):
        with patch("httpx.Client") as mock_client:
            ctx = mock_client.return_value.__enter__.return_value
            ctx.post.return_value = MagicMock()
            ae._send_pagerduty_event("K", _alert(severity="weird"))
        assert ctx.post.call_args.kwargs["json"]["payload"]["severity"] == "info"


class TestEmailNotification:
    def test_delegates_to_email_service(self):
        with patch("app.services.email_service.send_email") as mock_send:
            mock_send.return_value = True
            ae._send_email_notification("u@x.com", _alert())
        mock_send.assert_called_once()
        args, _ = mock_send.call_args
        assert args[0] == ["u@x.com"]
        assert "EASM Alert" in args[1]


class TestSendViaChannel:
    def test_slack_routed(self):
        with patch.object(ae, "settings", _Settings()):
            with patch.object(ae, "_send_slack_message") as mock:
                ae._send_via_channel(
                    {"type": "slack", "webhook_url": "https://s"},
                    _alert(),
                    MagicMock(),
                )
        mock.assert_called_once()

    def test_email_routed(self):
        with patch.object(ae, "_send_email_notification") as mock:
            ae._send_via_channel({"type": "email", "to": "a@b.com"}, _alert(), MagicMock())
        mock.assert_called_once()

    def test_webhook_routed(self):
        with patch.object(ae, "settings", _Settings()):
            with patch.object(ae, "_send_webhook_message") as mock:
                ae._send_via_channel(
                    {"type": "webhook", "webhook_url": "https://x"},
                    _alert(),
                    MagicMock(),
                )
        mock.assert_called_once()

    def test_teams_routed(self):
        with patch.object(ae, "_send_teams_message") as mock:
            ae._send_via_channel(
                {"type": "teams", "webhook_url": "https://teams"},
                _alert(),
                MagicMock(),
            )
        mock.assert_called_once()

    def test_pagerduty_routed(self):
        with patch.object(ae, "_send_pagerduty_event") as mock:
            ae._send_via_channel(
                {"type": "pagerduty", "routing_key": "KEY"},
                _alert(),
                MagicMock(),
            )
        mock.assert_called_once()

    def test_unknown_channel_logs_warning(self):
        tenant_logger = MagicMock()
        ae._send_via_channel({"type": "???"}, _alert(), tenant_logger)
        tenant_logger.warning.assert_called_once()

    def test_slack_no_url_skips(self):
        with patch.object(ae, "settings", _Settings()):
            with patch.object(ae, "_send_slack_message") as mock:
                ae._send_via_channel({"type": "slack"}, _alert(), MagicMock())
        mock.assert_not_called()

    def test_email_no_recipient_skips(self):
        with patch.object(ae, "_send_email_notification") as mock:
            ae._send_via_channel({"type": "email"}, _alert(), MagicMock())
        mock.assert_not_called()


class TestDeliverToChannels:
    def test_empty_channels(self):
        policy = _policy(channels=[])
        assert ae._deliver_to_channels(policy, _alert(), MagicMock()) == []

    def test_success(self):
        policy = _policy(channels=[{"type": "slack", "webhook_url": "u"}])
        with patch.object(ae, "_send_via_channel") as mock:
            channels = ae._deliver_to_channels(policy, _alert(), MagicMock())
        mock.assert_called_once()
        assert channels == ["slack"]

    def test_failure_does_not_raise(self):
        policy = _policy(channels=[{"type": "slack", "webhook_url": "u"}])
        tenant_logger = MagicMock()
        with patch.object(ae, "_send_via_channel", side_effect=RuntimeError("boom")):
            channels = ae._deliver_to_channels(policy, _alert(), tenant_logger)
        assert channels == []
        tenant_logger.exception.assert_called()
