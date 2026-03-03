"""
Celery task for scheduled report delivery.

Periodically queries active ReportSchedule rows, determines which are due
for delivery based on cadence and last_sent_at, generates the report via
``ReportGenerator``, and emails it as an attachment using SMTP.
"""

from __future__ import annotations

import json
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.report_schedule import ReportSchedule

logger = logging.getLogger(__name__)

# Cadence thresholds: minimum interval between deliveries for each schedule type
_CADENCE_INTERVALS = {
    "daily": timedelta(hours=23),
    "weekly": timedelta(days=6, hours=23),
    "monthly": timedelta(days=27),
}

# MIME types per format
_MIME_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

# File extensions per format
_EXTENSIONS = {
    "pdf": "pdf",
    "docx": "docx",
}


def _is_due(schedule: ReportSchedule) -> bool:
    """Determine whether a schedule is due for delivery.

    A schedule is due if it has never been sent (``last_sent_at`` is None)
    or if the elapsed time since the last delivery exceeds the cadence
    threshold.
    """
    if schedule.last_sent_at is None:
        return True

    interval = _CADENCE_INTERVALS.get(schedule.schedule)
    if interval is None:
        logger.warning(
            "Unknown schedule cadence '%s' for schedule %d, skipping",
            schedule.schedule,
            schedule.id,
        )
        return False

    elapsed = datetime.now(timezone.utc) - schedule.last_sent_at.replace(tzinfo=timezone.utc)
    return elapsed >= interval


def _generate_report(
    tenant_id: int,
    report_type: str,
    fmt: str,
) -> Optional[bytes]:
    """Generate a report (PDF or DOCX) for the given tenant.

    Opens its own database session to avoid sharing sessions across
    threads.

    Returns:
        Report bytes, or ``None`` if generation fails.
    """
    from app.services.report_generator import ReportGenerator

    db = SessionLocal()
    try:
        generator = ReportGenerator(db, tenant_id)
        if fmt == "pdf":
            return generator.generate_pdf(report_type=report_type)
        return generator.generate_docx(report_type=report_type)
    except Exception:
        logger.exception(
            "Failed to generate %s %s report for tenant %d",
            report_type,
            fmt,
            tenant_id,
        )
        return None
    finally:
        db.close()


def _send_email(
    recipients: list[str],
    subject: str,
    body_text: str,
    attachment: bytes,
    attachment_filename: str,
    attachment_mime: str,
) -> bool:
    """Send an email with a report attachment via SMTP.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    if not settings.smtp_host or not settings.smtp_from:
        logger.warning(
            "SMTP not configured (smtp_host=%s, smtp_from=%s). "
            "Skipping email delivery.",
            settings.smtp_host,
            settings.smtp_from,
        )
        return False

    msg = MIMEMultipart()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    # Plain-text body
    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    # Attachment
    part = MIMEApplication(attachment, Name=attachment_filename)
    part["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
    # Override the default Content-Type set by MIMEApplication
    part.set_type(attachment_mime)
    msg.attach(part)

    try:
        if settings.smtp_port == 465:
            # SSL connection
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

        logger.info(
            "Email sent to %s (subject: %s)",
            ", ".join(recipients),
            subject,
        )
        return True
    except smtplib.SMTPException:
        logger.exception("SMTP delivery failed for recipients %s", recipients)
        return False


@celery.task(
    name="app.tasks.report_delivery.deliver_scheduled_reports",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def deliver_scheduled_reports(self) -> dict:
    """
    Celery task: evaluate all active report schedules and deliver those
    that are due.

    Returns a summary dict with counts of processed, sent, and failed
    deliveries.
    """
    db = SessionLocal()
    processed = 0
    sent = 0
    failed = 0

    try:
        active_schedules = (
            db.query(ReportSchedule)
            .filter(ReportSchedule.is_active.is_(True))
            .all()
        )

        logger.info(
            "Report delivery task started: %d active schedule(s) found",
            len(active_schedules),
        )

        for schedule in active_schedules:
            if not _is_due(schedule):
                continue

            processed += 1

            # Parse recipients
            try:
                recipients = json.loads(schedule.recipients)
            except (json.JSONDecodeError, TypeError):
                logger.error(
                    "Invalid recipients JSON for schedule %d, skipping",
                    schedule.id,
                )
                failed += 1
                continue

            if not recipients:
                logger.warning(
                    "Empty recipients list for schedule %d, skipping",
                    schedule.id,
                )
                failed += 1
                continue

            # Generate report
            report_bytes = _generate_report(
                tenant_id=schedule.tenant_id,
                report_type=schedule.report_type,
                fmt=schedule.format,
            )

            if report_bytes is None:
                failed += 1
                continue

            # Build filename and subject
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
            ext = _EXTENSIONS.get(schedule.format, schedule.format)
            filename = (
                f"easm_{schedule.report_type}_tenant_{schedule.tenant_id}"
                f"_{timestamp}.{ext}"
            )
            subject = (
                f"[EASM] Scheduled {schedule.report_type.capitalize()} Report "
                f"- {schedule.name}"
            )
            body = (
                f"Attached is the scheduled {schedule.report_type} report "
                f"'{schedule.name}' generated on "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
                "This is an automated delivery from the EASM Platform."
            )
            mime_type = _MIME_TYPES.get(schedule.format, "application/octet-stream")

            # Send email
            success = _send_email(
                recipients=recipients,
                subject=subject,
                body_text=body,
                attachment=report_bytes,
                attachment_filename=filename,
                attachment_mime=mime_type,
            )

            if success:
                sent += 1
                schedule.last_sent_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(
                    "Delivered report schedule %d (%s %s) to %d recipient(s)",
                    schedule.id,
                    schedule.report_type,
                    schedule.format,
                    len(recipients),
                )
            else:
                failed += 1
                logger.warning(
                    "Failed to deliver report schedule %d",
                    schedule.id,
                )

    except Exception as exc:
        logger.exception("Unexpected error in deliver_scheduled_reports task")
        try:
            db.rollback()
        except Exception:
            pass
        raise self.retry(exc=exc)
    finally:
        db.close()

    summary = {"processed": processed, "sent": sent, "failed": failed}
    logger.info("Report delivery task completed: %s", summary)
    return summary
