"""
SQLAlchemy model for scheduled report delivery.

Stores configuration for automated PDF/DOCX report generation and
email delivery on daily, weekly, or monthly cadences.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.models.database import Base


class ReportSchedule(Base):
    """Scheduled report delivery configuration per tenant."""

    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # 'executive' or 'technical'
    format = Column(String(10), nullable=False)  # 'pdf' or 'docx'
    schedule = Column(String(50), nullable=False)  # 'daily', 'weekly', 'monthly'
    recipients = Column(Text, nullable=False)  # JSON array of email addresses
    is_active = Column(Boolean, default=True, nullable=False)
    last_sent_at = Column(DateTime, nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tenant = relationship("Tenant")

    def __repr__(self) -> str:
        return (
            f"<ReportSchedule(id={self.id}, name='{self.name}', "
            f"schedule='{self.schedule}', is_active={self.is_active})>"
        )
