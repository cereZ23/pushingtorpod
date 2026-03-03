from __future__ import annotations

"""
Issue Schemas

Pydantic models for issue lifecycle management, including state transitions,
activity tracking, and assignment.
"""

from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime

from app.api.schemas.finding import FindingResponse


class IssueResponse(BaseModel):
    """Issue list/detail response."""

    id: int = Field(..., description="Issue ID")
    tenant_id: int = Field(..., description="Tenant ID")
    project_id: Optional[int] = Field(None, description="Project ID")
    title: str = Field(..., description="Issue title")
    description: Optional[str] = Field(None, description="Issue description")
    root_cause: Optional[str] = Field(None, description="Root cause clustering key")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    confidence: Optional[float] = Field(None, description="Confidence score 0.0-1.0")
    status: str = Field(..., description="Issue status")
    affected_assets_count: int = Field(0, description="Number of affected assets")
    finding_count: int = Field(0, description="Number of linked findings")
    risk_score: float = Field(0.0, description="Risk score 0-100")
    assigned_to: Optional[int] = Field(None, description="Assigned user ID")
    assigned_to_name: Optional[str] = Field(None, description="Assigned user display name")
    ticket_ref: Optional[str] = Field(None, description="External ticket reference")
    sla_due_at: Optional[datetime] = Field(None, description="SLA deadline")
    resolved_at: Optional[datetime] = Field(None, description="Resolution timestamp")
    resolved_by: Optional[int] = Field(None, description="Resolved by user ID")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Last updated timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 42,
                "tenant_id": 1,
                "project_id": None,
                "title": "Missing HSTS header across web assets",
                "description": "Multiple web assets lack HTTP Strict Transport Security headers.",
                "root_cause": "missing-hsts",
                "severity": "medium",
                "confidence": 0.95,
                "status": "open",
                "affected_assets_count": 12,
                "finding_count": 15,
                "risk_score": 45.0,
                "assigned_to": None,
                "assigned_to_name": None,
                "ticket_ref": None,
                "sla_due_at": "2026-03-27T00:00:00Z",
                "resolved_at": None,
                "resolved_by": None,
                "created_at": "2026-02-25T10:00:00Z",
                "updated_at": "2026-02-25T10:00:00Z",
            }
        },
    )


class IssueCommentResponse(BaseModel):
    """Comment on an issue, stored as IssueActivity with action='comment'."""

    id: int = Field(..., description="Activity ID")
    issue_id: int = Field(..., description="Issue ID")
    author_id: Optional[int] = Field(None, description="Author user ID")
    author_name: str = Field("System", description="Author display name")
    content: str = Field("", description="Comment content")
    created_at: datetime = Field(..., description="Comment timestamp")

    model_config = ConfigDict(from_attributes=True)


class IssueActivityResponse(BaseModel):
    """Single activity entry in the issue timeline."""

    id: int = Field(..., description="Activity ID")
    issue_id: int = Field(..., description="Issue ID")
    user_id: Optional[int] = Field(None, description="User who performed the action")
    actor_name: str = Field("System", description="Display name of the actor")
    action: str = Field(..., description="Action type (status_change, comment, assign, sla_update)")
    old_value: Optional[str] = Field(None, description="Previous value")
    new_value: Optional[str] = Field(None, description="New value")
    comment: Optional[str] = Field(None, description="Comment text")
    details: Optional[str] = Field(None, description="Human-readable description of the change")
    created_at: datetime = Field(..., description="Activity timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 101,
                "issue_id": 42,
                "user_id": 3,
                "actor_name": "admin",
                "action": "status_change",
                "old_value": "open",
                "new_value": "triaged",
                "comment": "Confirmed and triaged.",
                "details": "Changed status from open to triaged",
                "created_at": "2026-02-25T11:30:00Z",
            }
        },
    )


class IssueDetailResponse(IssueResponse):
    """Extended issue detail including linked findings, activity, and comments."""

    findings: List[FindingResponse] = Field(
        default_factory=list,
        description="Linked findings with full details",
    )
    activity: List[IssueActivityResponse] = Field(
        default_factory=list,
        description="Activity timeline (status changes, assignments)",
    )
    comments: List[IssueCommentResponse] = Field(
        default_factory=list,
        description="Comments on this issue",
    )

    model_config = ConfigDict(from_attributes=True)


class IssueUpdate(BaseModel):
    """Partial update for an issue (status, assignment, fields)."""

    status: Optional[str] = Field(None, description="New status value")
    title: Optional[str] = Field(None, description="Updated title")
    description: Optional[str] = Field(None, description="Updated description")
    severity: Optional[str] = Field(None, description="Updated severity")
    assigned_to: Optional[int] = Field(None, description="Assign to user ID")
    ticket_ref: Optional[str] = Field(None, description="External ticket reference")
    comment: Optional[str] = Field(
        None,
        description="Required when transitioning to false_positive or accepted_risk",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "triaged",
                "assigned_to": 5,
                "comment": "Triaged and assigned to security team.",
            }
        }
    )


class IssueCommentCreate(BaseModel):
    """Request body for adding a comment to an issue.

    Accepts either ``comment`` or ``content`` as the field name so that
    both the legacy backend convention and the frontend convention work.
    """

    comment: Optional[str] = Field(None, min_length=1, max_length=5000, description="Comment text")
    content: Optional[str] = Field(None, min_length=1, max_length=5000, description="Comment text (alias)")

    @property
    def resolved_comment(self) -> str:
        """Return the comment text regardless of which field was used."""
        return self.comment or self.content or ""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "comment": "Confirmed this affects production. Escalating to infra team.",
            }
        }
    )


class IssueAssignRequest(BaseModel):
    """Request body for assigning an issue to a user."""

    assigned_to: int = Field(..., description="User ID to assign the issue to")
    comment: Optional[str] = Field(None, description="Optional comment about the assignment")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "assigned_to": 7,
                "comment": "Assigning to backend team lead for remediation.",
            }
        }
    )


# Rebuild models to resolve any forward references
IssueDetailResponse.model_rebuild()
