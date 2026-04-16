"""
Unit tests for app/services/email_service.py

Covers:
- send_email: no SMTP config returns False
- send_email: SMTP_SSL path (port 465)
- send_email: STARTTLS path (port 587)
- send_email: no auth when credentials missing
- send_email: SMTPException caught -> False
- send_invitation_email: wraps send_email with proper subject/url
- send_password_reset_email: wraps send_email with proper subject/url
"""

from __future__ import annotations

import smtplib
from unittest.mock import MagicMock, patch

import pytest

from app.services import email_service


class _FakeSettings:
    def __init__(
        self,
        smtp_host="mail.example.com",
        smtp_port=587,
        smtp_from="noreply@example.com",
        smtp_user=None,
        smtp_password=None,
        saml_frontend_url="https://app.example.com/",
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_from = smtp_from
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.saml_frontend_url = saml_frontend_url


class TestSendEmail:
    def test_no_smtp_host_returns_false(self):
        with patch.object(email_service, "settings", _FakeSettings(smtp_host=None)):
            result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is False

    def test_no_smtp_from_returns_false(self):
        with patch.object(email_service, "settings", _FakeSettings(smtp_from=None)):
            result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is False

    def test_starttls_flow(self):
        with patch.object(email_service, "settings", _FakeSettings(smtp_port=587)):
            with patch("smtplib.SMTP") as mock_smtp:
                server = mock_smtp.return_value
                result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>", text="hi")
        assert result is True
        server.ehlo.assert_called()
        server.starttls.assert_called_once()
        server.sendmail.assert_called_once()
        server.quit.assert_called_once()

    def test_ssl_flow(self):
        with patch.object(email_service, "settings", _FakeSettings(smtp_port=465)):
            with patch("smtplib.SMTP_SSL") as mock_ssl:
                server = mock_ssl.return_value
                result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is True
        server.sendmail.assert_called_once()
        server.quit.assert_called_once()

    def test_with_auth_credentials(self):
        with patch.object(
            email_service,
            "settings",
            _FakeSettings(smtp_user="user", smtp_password="pass"),
        ):
            with patch("smtplib.SMTP") as mock_smtp:
                server = mock_smtp.return_value
                result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is True
        server.login.assert_called_once_with("user", "pass")

    def test_without_auth_credentials(self):
        # Missing user/password -> no login call
        with patch.object(email_service, "settings", _FakeSettings()):
            with patch("smtplib.SMTP") as mock_smtp:
                server = mock_smtp.return_value
                result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is True
        server.login.assert_not_called()

    def test_smtp_exception_returns_false(self):
        with patch.object(email_service, "settings", _FakeSettings()):
            with patch("smtplib.SMTP") as mock_smtp:
                mock_smtp.return_value.sendmail.side_effect = smtplib.SMTPException("boom")
                result = email_service.send_email(["a@b.com"], "S", "<p>hi</p>")
        assert result is False


class TestSendInvitationEmail:
    def test_calls_send_email_with_invite_url(self):
        with patch.object(email_service, "settings", _FakeSettings()):
            with patch.object(email_service, "send_email") as mock_send:
                mock_send.return_value = True
                result = email_service.send_invitation_email("invitee@example.com", "tok123", "Acme", "Alice")
        assert result is True
        # Verify call
        args, kwargs = mock_send.call_args
        recipients, subject, html, text = args[0], args[1], args[2], args[3]
        assert recipients == ["invitee@example.com"]
        assert "Acme" in subject
        assert "accept-invite?token=tok123" in html
        assert "Alice" in text


class TestSendPasswordResetEmail:
    def test_calls_send_email_with_reset_url(self):
        with patch.object(email_service, "settings", _FakeSettings()):
            with patch.object(email_service, "send_email") as mock_send:
                mock_send.return_value = True
                result = email_service.send_password_reset_email("user@example.com", "reset-tok")
        assert result is True
        args, kwargs = mock_send.call_args
        recipients, subject, html, text = args[0], args[1], args[2], args[3]
        assert recipients == ["user@example.com"]
        assert "Password Reset" in subject
        assert "reset-password?token=reset-tok" in html

    def test_strips_trailing_slash_from_frontend_url(self):
        with patch.object(email_service, "settings", _FakeSettings(saml_frontend_url="https://x/")):
            with patch.object(email_service, "send_email") as mock_send:
                mock_send.return_value = True
                email_service.send_password_reset_email("u@e.com", "t")
        args, _ = mock_send.call_args
        assert "https://x/reset-password?token=t" in args[2]
