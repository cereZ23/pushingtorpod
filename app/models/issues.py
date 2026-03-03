"""
Issue lifecycle models for grouped finding management

Provides Issue, IssueFinding, and IssueActivity models that allow
grouping related findings into actionable issues with workflow
tracking, assignment, and SLA management.
"""

import enum
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text, Enum, Float, Index,
)
from sqlalchemy.orm import relationship

from app.models.database import Base


class IssueStatus(enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    VERIFYING = "verifying"
    VERIFIED_FIXED = "verified_fixed"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Issue(Base):
    """
    Aggregated issue grouping one or more findings by root cause.

    Issues provide a lifecycle workflow around findings, supporting
    assignment, SLA tracking, and integration with external ticketing
    systems.
    """

    __tablename__ = 'issues'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    project_id = Column(Integer, ForeignKey('projects.id'))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    root_cause = Column(String(255))  # Clustering key (e.g., "missing-hsts", "CVE-2024-1234")
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    confidence = Column(Float, default=1.0)  # 0.0-1.0
    status = Column(Enum(IssueStatus), default=IssueStatus.OPEN)
    affected_assets_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)  # 0-100
    assigned_to = Column(Integer, ForeignKey('users.id'))
    ticket_ref = Column(String(255))  # External ticket ID
    sla_due_at = Column(DateTime)
    resolved_at = Column(DateTime)
    resolved_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    issue_findings = relationship(
        "IssueFinding", back_populates="issue", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index('idx_issue_tenant', 'tenant_id'),
        Index('idx_issue_project', 'project_id'),
        Index('idx_issue_status', 'status'),
        Index('idx_issue_severity', 'severity'),
        Index('idx_issue_sla', 'sla_due_at'),
        Index('idx_issue_root_cause', 'tenant_id', 'root_cause'),
    )

    def __repr__(self):
        return f"<Issue(id={self.id}, title='{self.title}', status={self.status.value})>"


class IssueFinding(Base):
    """
    Association between issues and findings (many-to-many).

    A finding can belong to at most one issue; the unique index on
    (issue_id, finding_id) enforces deduplication.
    """

    __tablename__ = 'issue_findings'

    id = Column(Integer, primary_key=True)
    issue_id = Column(Integer, ForeignKey('issues.id', ondelete='CASCADE'), nullable=False)
    finding_id = Column(Integer, ForeignKey('findings.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    issue = relationship("Issue", back_populates="issue_findings")

    __table_args__ = (
        Index('idx_if_issue', 'issue_id'),
        Index('idx_if_finding', 'finding_id'),
        Index('idx_if_unique', 'issue_id', 'finding_id', unique=True),
    )

    def __repr__(self):
        return f"<IssueFinding(id={self.id}, issue_id={self.issue_id}, finding_id={self.finding_id})>"


class IssueActivity(Base):
    """
    Activity log for issue state changes and comments.

    Tracks every mutation on an issue: status transitions, assignments,
    SLA updates, and free-form comments for audit purposes.
    """

    __tablename__ = 'issue_activities'

    id = Column(Integer, primary_key=True)
    issue_id = Column(Integer, ForeignKey('issues.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(50), nullable=False)  # 'status_change', 'comment', 'assign', 'sla_update'
    old_value = Column(String(255))
    new_value = Column(String(255))
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_ia_issue', 'issue_id'),
        Index('idx_ia_created', 'created_at'),
    )

    def __repr__(self):
        return f"<IssueActivity(id={self.id}, issue_id={self.issue_id}, action='{self.action}')>"
