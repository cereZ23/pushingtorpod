"""
Email Service

Reusable email sending functions for invitations, password resets,
and general notifications. Extracted from report_delivery._send_email.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger(__name__)


def send_email(
    recipients: list[str],
    subject: str,
    html: str,
    text: str | None = None,
) -> bool:
    """Send an email via SMTP.

    Returns True if sent successfully, False otherwise.
    """
    if not settings.smtp_host or not settings.smtp_from:
        logger.warning(
            "SMTP not configured (smtp_host=%s, smtp_from=%s). Skipping email.",
            settings.smtp_host,
            settings.smtp_from,
        )
        return False

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    if text:
        msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()

        if settings.smtp_user and settings.smtp_password:
            server.login(settings.smtp_user, settings.smtp_password)

        server.sendmail(settings.smtp_from, recipients, msg.as_string())
        server.quit()

        logger.info("Email sent to %s (subject: %s)", ", ".join(recipients), subject)
        return True
    except smtplib.SMTPException:
        logger.exception("SMTP delivery failed for recipients %s", recipients)
        return False


def send_invitation_email(
    email: str,
    token: str,
    tenant_name: str,
    inviter_name: str,
) -> bool:
    """Send a tenant invitation email."""
    frontend_url = settings.saml_frontend_url.rstrip("/")
    accept_url = f"{frontend_url}/accept-invite?token={token}"

    subject = f"[EASM] You've been invited to {tenant_name}"
    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1e293b;">You've been invited to {tenant_name}</h2>
        <p style="color: #475569;">{inviter_name} has invited you to join <strong>{tenant_name}</strong> on the EASM Platform.</p>
        <p style="margin: 24px 0;">
            <a href="{accept_url}"
               style="display: inline-block; padding: 12px 24px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Accept Invitation
            </a>
        </p>
        <p style="color: #94a3b8; font-size: 14px;">This invitation expires in 7 days. If you didn't expect this, you can ignore this email.</p>
    </div>
    """
    text = (
        f"{inviter_name} has invited you to join {tenant_name} on the EASM Platform.\n\n"
        f"Accept your invitation: {accept_url}\n\n"
        "This invitation expires in 7 days."
    )

    return send_email([email], subject, html, text)


def send_password_reset_email(email: str, token: str) -> bool:
    """Send a password reset email."""
    frontend_url = settings.saml_frontend_url.rstrip("/")
    reset_url = f"{frontend_url}/reset-password?token={token}"

    subject = "[EASM] Password Reset Request"
    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1e293b;">Password Reset</h2>
        <p style="color: #475569;">We received a request to reset your password for the EASM Platform.</p>
        <p style="margin: 24px 0;">
            <a href="{reset_url}"
               style="display: inline-block; padding: 12px 24px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Reset Password
            </a>
        </p>
        <p style="color: #94a3b8; font-size: 14px;">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>
    </div>
    """
    text = (
        "We received a request to reset your EASM Platform password.\n\n"
        f"Reset your password: {reset_url}\n\n"
        "This link expires in 1 hour. If you didn't request this, ignore this email."
    )

    return send_email([email], subject, html, text)
