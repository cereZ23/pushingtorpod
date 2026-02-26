"""
Issue Lifecycle API router.

Issues group related findings by root cause. They follow a state machine:
open -> triaged -> in_progress -> mitigated -> verifying -> verified_fixed -> closed
Any non-terminal state can transition to false_positive or accepted_risk.

SLA auto-population: Critical=48h, High=7d, Medium=30d, Low=90d
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_current_user,
    get_db,
    PaginationParams,
    verify_tenant_access,
    escape_like,
)
from app.api.schemas.common import PaginatedResponse
from app.api.schemas.issue import (
    IssueActivityResponse,
    IssueAssignRequest,
    IssueCommentCreate,
    IssueCommentResponse,
    IssueDetailResponse,
    IssueResponse,
    IssueUpdate,
)
from app.api.schemas.finding import FindingResponse
from app.models.auth import User
from app.models.database import Asset, Finding, FindingStatus
from app.models.issues import Issue, IssueActivity, IssueFinding, IssueStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["Issues"])

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[str, list[str]] = {
    "open": ["triaged", "false_positive", "accepted_risk"],
    "triaged": ["in_progress", "false_positive", "accepted_risk"],
    "in_progress": ["mitigated", "false_positive", "accepted_risk"],
    "mitigated": ["verifying"],
    "verifying": ["verified_fixed", "open"],
    "verified_fixed": ["closed"],
    "closed": ["open"],
    "false_positive": ["closed"],
    "accepted_risk": ["closed"],
}

# ---------------------------------------------------------------------------
# SLA windows per severity
# ---------------------------------------------------------------------------

SLA_WINDOWS: dict[str, timedelta] = {
    "critical": timedelta(hours=48),
    "high": timedelta(days=7),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_issue_or_404(
    issue_id: int,
    tenant_id: int,
    db: Session,
) -> Issue:
    """Fetch an issue scoped to the tenant, or raise 404."""
    issue = (
        db.query(Issue)
        .filter(Issue.id == issue_id, Issue.tenant_id == tenant_id)
        .first()
    )
    if not issue:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issue not found",
        )
    return issue


def _create_activity(
    db: Session,
    issue_id: int,
    user_id: int,
    action: str,
    old_value: Optional[str] = None,
    new_value: Optional[str] = None,
    comment: Optional[str] = None,
) -> IssueActivity:
    """Create an IssueActivity record and flush it to the session."""
    activity = IssueActivity(
        issue_id=issue_id,
        user_id=user_id,
        action=action,
        old_value=old_value,
        new_value=new_value,
        comment=comment,
    )
    db.add(activity)
    db.flush()
    return activity


def _resolve_assigned_to_name(
    db: Session,
    user_id: Optional[int],
) -> Optional[str]:
    """Resolve the display name for the assigned user."""
    if user_id is None:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        return None
    return user.full_name or user.username


def _issue_to_response(issue: Issue, db: Session) -> IssueResponse:
    """Convert an Issue ORM object to an IssueResponse with assigned_to_name."""
    data = IssueResponse.model_validate(issue).model_dump()
    data["assigned_to_name"] = _resolve_assigned_to_name(db, issue.assigned_to)
    return IssueResponse(**data)


def _cascade_findings_status(
    db: Session,
    issue: Issue,
    new_status: str,
    user_id: int,
) -> None:
    """Apply cascade effects to linked findings when the issue status changes.

    Cascade rules:
      - false_positive:  linked findings -> suppressed, set resolved fields
      - accepted_risk:   no finding status change (note tracked via activity)
      - mitigated:       linked findings -> suppressed (closest semantic match)
      - verified_fixed:  linked findings -> fixed, set resolved fields
      - closed:          linked findings -> fixed
      - open (reopen):   linked closed/suppressed findings -> open, clear resolved
    """
    finding_ids = [
        row[0]
        for row in db.query(IssueFinding.finding_id)
        .filter(IssueFinding.issue_id == issue.id)
        .all()
    ]

    if not finding_ids:
        return

    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    now = datetime.now(timezone.utc)

    if new_status == "false_positive":
        for finding in findings:
            finding.status = FindingStatus.SUPPRESSED
            finding.last_seen = now

    elif new_status == "mitigated":
        for finding in findings:
            finding.status = FindingStatus.SUPPRESSED
            finding.last_seen = now

    elif new_status == "verified_fixed":
        for finding in findings:
            finding.status = FindingStatus.FIXED
            finding.last_seen = now

    elif new_status == "closed":
        for finding in findings:
            finding.status = FindingStatus.FIXED
            finding.last_seen = now

    elif new_status == "open":
        # Reopen: only touch findings that were closed/suppressed
        for finding in findings:
            if finding.status in (FindingStatus.FIXED, FindingStatus.SUPPRESSED):
                finding.status = FindingStatus.OPEN

    # accepted_risk: no finding status change
    db.flush()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/issues", response_model=PaginatedResponse[IssueResponse])
def list_issues(
    tenant_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by issue status"
    ),
    assigned_to: Optional[int] = Query(None, description="Filter by assigned user"),
    project_id: Optional[int] = Query(None, description="Filter by project"),
    search: Optional[str] = Query(None, description="Search in title, description, root_cause"),
    sort_by: str = Query("created_at", description="Sort field"),
    order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> PaginatedResponse[IssueResponse]:
    """List issues with filtering, search, and pagination.

    Supports filtering by severity, status, assignment, and project.
    Full-text search across title, description, and root_cause fields.
    """
    query = db.query(Issue).filter(Issue.tenant_id == tenant_id)

    # -- Filters ---------------------------------------------------------------

    if severity:
        if severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}. Must be one of {sorted(VALID_SEVERITIES)}",
            )
        query = query.filter(Issue.severity == severity)

    if status_filter:
        try:
            IssueStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}",
            )
        query = query.filter(Issue.status == IssueStatus(status_filter))

    if assigned_to is not None:
        query = query.filter(Issue.assigned_to == assigned_to)

    if project_id is not None:
        query = query.filter(Issue.project_id == project_id)

    if search:
        safe_search = escape_like(search)
        like_pattern = f"%{safe_search}%"
        query = query.filter(
            or_(
                Issue.title.ilike(like_pattern, escape="\\"),
                Issue.description.ilike(like_pattern, escape="\\"),
                Issue.root_cause.ilike(like_pattern, escape="\\"),
            )
        )

    # -- Count -----------------------------------------------------------------

    total = query.count()

    # -- Sorting ---------------------------------------------------------------

    ALLOWED_SORT_COLUMNS = {
        "title": Issue.title,
        "severity": Issue.severity,
        "status": Issue.status,
        "created_at": Issue.created_at,
        "updated_at": Issue.updated_at,
        "sla_deadline": Issue.sla_deadline,
        "risk_score": Issue.risk_score,
    }
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by, Issue.created_at)
    if order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # -- Pagination ------------------------------------------------------------

    query = pagination.paginate_query(query)
    issues = query.all()

    items = [_issue_to_response(issue, db) for issue in issues]

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size,
    )


@router.get("/issues/{issue_id}", response_model=IssueDetailResponse)
def get_issue(
    tenant_id: int,
    issue_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> IssueDetailResponse:
    """Get full issue detail with linked findings, activity timeline, and comments."""
    issue = _get_issue_or_404(issue_id, tenant_id, db)

    # --- Linked findings (full objects) ------------------------------------
    linked_findings = (
        db.query(Finding)
        .join(IssueFinding, IssueFinding.finding_id == Finding.id)
        .filter(IssueFinding.issue_id == issue.id)
        .all()
    )

    # Enrich each finding with its asset identifier / type
    finding_responses: List[FindingResponse] = []
    for f in linked_findings:
        data = FindingResponse.model_validate(f).model_dump()
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        if asset:
            data["asset_identifier"] = asset.identifier
            data["asset_type"] = asset.type if hasattr(asset, "type") else None
        finding_responses.append(FindingResponse(**data))

    # --- Activity timeline (non-comment entries) ---------------------------
    activities = (
        db.query(IssueActivity)
        .filter(
            IssueActivity.issue_id == issue.id,
            IssueActivity.action != "comment",
        )
        .order_by(IssueActivity.created_at.asc())
        .all()
    )

    activity_items: List[IssueActivityResponse] = []
    for act in activities:
        act_data = IssueActivityResponse.model_validate(act).model_dump()
        # Resolve actor_name from user_id
        actor_name = "System"
        if act.user_id:
            actor = db.query(User).filter(User.id == act.user_id).first()
            if actor:
                actor_name = actor.full_name or actor.username
        act_data["actor_name"] = actor_name
        # Build a human-readable details string
        if act.action == "status_change" and act.old_value and act.new_value:
            act_data["details"] = f"Changed status from {act.old_value} to {act.new_value}"
        elif act.action == "severity_change" and act.old_value and act.new_value:
            act_data["details"] = f"Changed severity from {act.old_value} to {act.new_value}"
        elif act.action == "assign":
            act_data["details"] = f"Assigned to user {act.new_value}"
        elif act.comment:
            act_data["details"] = act.comment
        activity_items.append(IssueActivityResponse(**act_data))

    # --- Comments (activity entries with action='comment') -----------------
    comment_rows = (
        db.query(IssueActivity)
        .filter(
            IssueActivity.issue_id == issue.id,
            IssueActivity.action == "comment",
        )
        .order_by(IssueActivity.created_at.asc())
        .all()
    )

    comment_items: List[IssueCommentResponse] = []
    for c in comment_rows:
        author_name = "System"
        if c.user_id:
            author = db.query(User).filter(User.id == c.user_id).first()
            if author:
                author_name = author.full_name or author.username
        comment_items.append(
            IssueCommentResponse(
                id=c.id,
                issue_id=c.issue_id,
                author_id=c.user_id,
                author_name=author_name,
                content=c.comment or "",
                created_at=c.created_at,
            )
        )

    # --- Build response ----------------------------------------------------
    base_data = _issue_to_response(issue, db).model_dump()
    base_data["findings"] = finding_responses
    base_data["activity"] = activity_items
    base_data["comments"] = comment_items

    return IssueDetailResponse(**base_data)


@router.patch("/issues/{issue_id}", response_model=IssueResponse)
def update_issue(
    tenant_id: int,
    issue_id: int,
    updates: IssueUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
    current_user: User = Depends(get_current_user),
) -> IssueResponse:
    """Update an issue (status transition, assignment, field edits).

    Status transitions are validated against the state machine. Transitioning
    to ``false_positive`` or ``accepted_risk`` requires a comment in the
    request body.  Every status change creates an ``IssueActivity`` record
    and cascades effects to linked findings.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    issue = _get_issue_or_404(issue_id, tenant_id, db)
    user_id: int = current_user.id

    # -- Status transition -----------------------------------------------------

    if updates.status is not None:
        try:
            new_status_enum = IssueStatus(updates.status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {updates.status}",
            )

        current_status_value = issue.status.value
        new_status_value = new_status_enum.value

        # Validate transition
        allowed = VALID_TRANSITIONS.get(current_status_value, [])
        if new_status_value not in allowed:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Invalid transition from '{current_status_value}' to "
                    f"'{new_status_value}'. Allowed: {allowed}"
                ),
            )

        # Require comment for terminal-like transitions
        if new_status_value in ("false_positive", "accepted_risk") and not updates.comment:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"A comment is required when transitioning to '{new_status_value}'",
            )

        # Apply status change
        old_status_value = current_status_value
        issue.status = new_status_enum

        # Set resolution metadata for terminal states
        if new_status_value in ("verified_fixed", "closed", "false_positive"):
            issue.resolved_at = datetime.now(timezone.utc)
            issue.resolved_by = user_id

        # Clear resolution metadata on reopen
        if new_status_value == "open" and old_status_value in ("closed", "verifying"):
            issue.resolved_at = None
            issue.resolved_by = None

        # Create activity record
        _create_activity(
            db=db,
            issue_id=issue.id,
            user_id=user_id,
            action="status_change",
            old_value=old_status_value,
            new_value=new_status_value,
            comment=updates.comment,
        )

        # Cascade to linked findings
        _cascade_findings_status(db, issue, new_status_value, user_id)

    # -- Field updates ---------------------------------------------------------

    if updates.title is not None:
        issue.title = updates.title

    if updates.description is not None:
        issue.description = updates.description

    if updates.severity is not None:
        if updates.severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {updates.severity}",
            )
        old_severity = issue.severity
        issue.severity = updates.severity

        # Recalculate SLA when severity changes
        sla_window = SLA_WINDOWS.get(updates.severity)
        if sla_window:
            issue.sla_due_at = datetime.now(timezone.utc) + sla_window

        _create_activity(
            db=db,
            issue_id=issue.id,
            user_id=user_id,
            action="severity_change",
            old_value=old_severity,
            new_value=updates.severity,
            comment=updates.comment,
        )

    if updates.assigned_to is not None:
        old_assigned = str(issue.assigned_to) if issue.assigned_to else None
        issue.assigned_to = updates.assigned_to

        _create_activity(
            db=db,
            issue_id=issue.id,
            user_id=user_id,
            action="assign",
            old_value=old_assigned,
            new_value=str(updates.assigned_to),
            comment=updates.comment,
        )

    if updates.ticket_ref is not None:
        issue.ticket_ref = updates.ticket_ref

    issue.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(issue)

    logger.info(
        "Updated issue %d (tenant %d) by user %d: status=%s",
        issue.id,
        tenant_id,
        user_id,
        issue.status.value,
    )

    return _issue_to_response(issue, db)


@router.post("/issues/{issue_id}/comment", response_model=IssueCommentResponse)
@router.post("/issues/{issue_id}/comments", response_model=IssueCommentResponse)
def add_comment(
    tenant_id: int,
    issue_id: int,
    body: IssueCommentCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
    current_user: User = Depends(get_current_user),
) -> IssueCommentResponse:
    """Add a comment to an issue.

    Creates an ``IssueActivity`` with action ``comment``.
    Accepts both ``/comment`` and ``/comments`` paths for compatibility.
    The request body may use either ``comment`` or ``content`` as the field name.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    issue = _get_issue_or_404(issue_id, tenant_id, db)

    comment_text = body.resolved_comment
    if not comment_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Comment text is required (provide 'comment' or 'content')",
        )

    activity = _create_activity(
        db=db,
        issue_id=issue.id,
        user_id=current_user.id,
        action="comment",
        comment=comment_text,
    )

    # Touch the issue updated_at timestamp
    issue.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(activity)

    logger.info(
        "Comment added to issue %d (tenant %d) by user %d",
        issue.id,
        tenant_id,
        current_user.id,
    )

    # Return in the format the frontend expects
    author_name = current_user.full_name or current_user.username
    return IssueCommentResponse(
        id=activity.id,
        issue_id=activity.issue_id,
        author_id=current_user.id,
        author_name=author_name,
        content=activity.comment or "",
        created_at=activity.created_at,
    )


@router.get(
    "/issues/{issue_id}/activities",
    response_model=PaginatedResponse[IssueActivityResponse],
)
def list_activities(
    tenant_id: int,
    issue_id: int,
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> PaginatedResponse[IssueActivityResponse]:
    """Get the activity timeline for an issue.

    Returns all activities (status changes, comments, assignments) in
    reverse chronological order.
    """
    # Validate the issue belongs to the tenant
    _get_issue_or_404(issue_id, tenant_id, db)

    query = (
        db.query(IssueActivity)
        .filter(IssueActivity.issue_id == issue_id)
        .order_by(IssueActivity.created_at.desc())
    )

    total = query.count()
    query = pagination.paginate_query(query)
    activities = query.all()

    items = [IssueActivityResponse.model_validate(a) for a in activities]

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size,
    )


@router.post("/issues/{issue_id}/assign", response_model=IssueResponse)
def assign_issue(
    tenant_id: int,
    issue_id: int,
    body: IssueAssignRequest,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
    current_user: User = Depends(get_current_user),
) -> IssueResponse:
    """Assign an issue to a user.

    Creates an ``IssueActivity`` with action ``assign`` and updates the
    ``assigned_to`` field on the issue.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    issue = _get_issue_or_404(issue_id, tenant_id, db)

    old_assigned = str(issue.assigned_to) if issue.assigned_to else None
    issue.assigned_to = body.assigned_to
    issue.updated_at = datetime.now(timezone.utc)

    _create_activity(
        db=db,
        issue_id=issue.id,
        user_id=current_user.id,
        action="assign",
        old_value=old_assigned,
        new_value=str(body.assigned_to),
        comment=body.comment,
    )

    db.commit()
    db.refresh(issue)

    logger.info(
        "Issue %d (tenant %d) assigned to user %d by user %d",
        issue.id,
        tenant_id,
        body.assigned_to,
        current_user.id,
    )

    return _issue_to_response(issue, db)
