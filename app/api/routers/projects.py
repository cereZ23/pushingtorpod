"""
Projects and Scan Management API router.

Provides endpoints for project CRUD, scan profile management,
scan execution, and progress monitoring.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
import logging

from app.core.audit import log_data_modification

from app.api.dependencies import (
    get_db,
    verify_tenant_access,
    PaginationParams,
    escape_like,
)
from app.api.schemas.common import PaginatedResponse, TaskResponse, SuccessResponse
from app.models.scanning import (
    Project,
    Scope,
    ScanProfile,
    ScanRun,
    ScanRunStatus,
    PhaseResult,
    PhaseStatus,
    Observation,
)
from app.models.database import Asset, Finding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["Projects & Scans"])


# ---------------------------------------------------------------------------
# Pydantic schemas (inline for this router)
# ---------------------------------------------------------------------------


class ProjectCreate(BaseModel):
    """Schema for creating a new project."""

    name: str = Field(..., max_length=255)
    description: str | None = None
    seeds: list[dict] | None = None  # [{"type": "domain", "value": "example.com"}]
    settings: dict | None = None


class ProjectUpdate(BaseModel):
    """Schema for updating a project."""

    name: str | None = Field(None, max_length=255)
    description: str | None = None
    seeds: list[dict] | None = None
    settings: dict | None = None


class ProjectResponse(BaseModel):
    """Schema returned for project objects."""

    id: int
    tenant_id: int
    name: str
    description: str | None
    seeds: list | None
    settings: dict | None
    created_by: int | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectDetailResponse(ProjectResponse):
    """Extended project response including aggregate statistics."""

    asset_count: int = 0
    finding_count: int = 0
    scan_run_count: int = 0
    last_scan_at: datetime | None = None


class ScopeCreate(BaseModel):
    """Schema for adding a scope rule."""

    rule_type: str = Field(..., pattern="^(include|exclude)$")
    match_type: str = Field(..., pattern="^(domain|ip|cidr|regex)$")
    pattern: str = Field(..., max_length=500)
    description: str | None = None


class ScopeResponse(BaseModel):
    """Schema returned for scope objects."""

    id: int
    project_id: int
    rule_type: str
    match_type: str
    pattern: str
    description: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanProfileCreate(BaseModel):
    """Schema for creating a scan profile."""

    name: str = Field(..., max_length=255)
    scan_tier: int = Field(1, ge=1, le=3)
    port_scan_mode: str = "top-100"
    nuclei_tags: list[str] | None = None
    schedule_cron: str | None = None
    max_rate_pps: int = 10
    timeout_minutes: int = 120


class ScanProfileResponse(BaseModel):
    """Schema returned for scan profile objects."""

    id: int
    project_id: int
    name: str
    scan_tier: int
    port_scan_mode: str
    nuclei_tags: list[str] | None
    schedule_cron: str | None
    max_rate_pps: int
    timeout_minutes: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScheduleUpdate(BaseModel):
    """Schema for updating a scan profile schedule."""

    schedule_cron: str | None = None  # null to clear


class ScanTrigger(BaseModel):
    """Schema for triggering a scan."""

    profile_id: int | None = None
    scan_tier: int = Field(1, ge=1, le=3, description="Scan tier: 1=Safe, 2=Moderate, 3=Aggressive")
    triggered_by: str = "manual"


class ScanRunResponse(BaseModel):
    """Schema returned for scan run objects."""

    id: int
    project_id: int
    profile_id: int | None
    tenant_id: int
    status: str
    triggered_by: str | None
    started_at: datetime | None
    completed_at: datetime | None
    stats: dict | None
    error_message: str | None
    celery_task_id: str | None
    created_at: datetime
    duration_seconds: int | None = None

    model_config = ConfigDict(from_attributes=True)


class PhaseResultResponse(BaseModel):
    """Schema returned for phase result objects."""

    id: int
    scan_run_id: int
    phase: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    stats: dict | None
    error_message: str | None
    duration_seconds: int | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanProgressResponse(BaseModel):
    """Schema for real-time scan progress."""

    scan_run: ScanRunResponse
    phases: list[PhaseResultResponse]


class ChangeEventResponse(BaseModel):
    """Schema for scan change events extracted from stats."""

    phase: str
    event_type: str
    detail: dict


class MonitoringStatusResponse(BaseModel):
    """Schema for project monitoring status."""

    project_id: int
    active_profiles: int
    scheduled_profiles: int
    running_scans: int
    last_completed_scan: ScanRunResponse | None
    next_scheduled_profile: ScanProfileResponse | None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _get_project_or_404(
    db: Session,
    tenant_id: int,
    project_id: int,
) -> Project:
    """Fetch a project scoped to the given tenant, or raise 404."""
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.tenant_id == tenant_id,
        )
        .first()
    )
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    return project


def _serialize_scan_run(scan_run: ScanRun) -> dict:
    """Convert a ScanRun ORM instance to a response-friendly dict."""
    return {
        "id": scan_run.id,
        "project_id": scan_run.project_id,
        "profile_id": scan_run.profile_id,
        "tenant_id": scan_run.tenant_id,
        "status": scan_run.status.value if hasattr(scan_run.status, "value") else str(scan_run.status),
        "triggered_by": scan_run.triggered_by,
        "started_at": scan_run.started_at,
        "completed_at": scan_run.completed_at,
        "stats": scan_run.stats,
        "error_message": scan_run.error_message,
        "celery_task_id": scan_run.celery_task_id,
        "created_at": scan_run.created_at,
        "duration_seconds": scan_run.duration_seconds,
    }


def _serialize_phase_result(phase: PhaseResult) -> dict:
    """Convert a PhaseResult ORM instance to a response-friendly dict."""
    return {
        "id": phase.id,
        "scan_run_id": phase.scan_run_id,
        "phase": phase.phase,
        "status": phase.status.value if hasattr(phase.status, "value") else str(phase.status),
        "started_at": phase.started_at,
        "completed_at": phase.completed_at,
        "stats": phase.stats,
        "error_message": phase.error_message,
        "duration_seconds": phase.duration_seconds,
    }


# ===========================================================================
# PROJECT ENDPOINTS
# ===========================================================================


@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    tenant_id: int,
    project_data: ProjectCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Create a new project with optional seeds.

    A project groups seeds, scope rules, scan profiles, and scan runs
    under a single organisational unit for a tenant.

    Args:
        tenant_id: Tenant ID (path)
        project_data: Project creation payload

    Returns:
        The created project

    Raises:
        403: Insufficient permissions
        400: Duplicate project name within the tenant
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    # Check for duplicate name within tenant
    existing = (
        db.query(Project)
        .filter(
            Project.tenant_id == tenant_id,
            Project.name == project_data.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project with name '{project_data.name}' already exists for this tenant",
        )

    project = Project(
        tenant_id=tenant_id,
        name=project_data.name,
        description=project_data.description,
        seeds=project_data.seeds,
        settings=project_data.settings,
        created_by=membership.user_id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    log_data_modification(
        action="create",
        resource="project",
        resource_id=str(project.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"name": project.name},
    )

    return ProjectResponse.model_validate(project)


@router.get("/projects", response_model=PaginatedResponse[ProjectResponse])
def list_projects(
    tenant_id: int,
    search: Optional[str] = Query(None, description="Search in project name"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List projects for a tenant with optional search and pagination.

    Args:
        tenant_id: Tenant ID (path)
        search: Optional name search filter
        pagination: Standard pagination parameters

    Returns:
        Paginated list of projects
    """
    query = db.query(Project).filter(Project.tenant_id == tenant_id)

    if search:
        safe_search = escape_like(search)
        query = query.filter(Project.name.ilike(f"%{safe_search}%", escape="\\"))

    total = query.count()
    query = query.order_by(Project.updated_at.desc())
    query = pagination.paginate_query(query)
    projects = query.all()

    return PaginatedResponse(
        items=[ProjectResponse.model_validate(p) for p in projects],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size if total else 0,
    )


@router.get("/projects/{project_id}", response_model=ProjectDetailResponse)
def get_project(
    tenant_id: int,
    project_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get project detail with aggregate statistics.

    Returns the project along with counts for assets, findings,
    scan runs, and the timestamp of the last completed scan.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)

    Returns:
        Project detail with stats

    Raises:
        404: Project not found
    """
    project = _get_project_or_404(db, tenant_id, project_id)

    # Count assets created via this project's scan runs
    asset_count = (
        db.query(func.count(Observation.id))
        .filter(Observation.scan_run_id.in_(db.query(ScanRun.id).filter(ScanRun.project_id == project_id)))
        .scalar()
        or 0
    )

    # Fall back to counting tenant assets when observations are sparse
    if asset_count == 0:
        asset_count = (
            db.query(func.count(Asset.id))
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.is_active == True,
            )
            .scalar()
            or 0
        )

    # Count findings through tenant scope
    finding_count = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
        )
        .scalar()
        or 0
    )

    # Count scan runs for this project
    scan_run_count = (
        db.query(func.count(ScanRun.id))
        .filter(
            ScanRun.project_id == project_id,
        )
        .scalar()
        or 0
    )

    # Last completed scan
    last_scan = (
        db.query(ScanRun)
        .filter(
            ScanRun.project_id == project_id,
            ScanRun.status == ScanRunStatus.COMPLETED,
        )
        .order_by(ScanRun.completed_at.desc())
        .first()
    )

    response = ProjectDetailResponse.model_validate(project)
    response.asset_count = asset_count
    response.finding_count = finding_count
    response.scan_run_count = scan_run_count
    response.last_scan_at = last_scan.completed_at if last_scan else None

    return response


@router.put("/projects/{project_id}", response_model=ProjectResponse)
def update_project(
    tenant_id: int,
    project_id: int,
    updates: ProjectUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Update an existing project.

    Allows partial updates of name, description, seeds, and settings.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        updates: Fields to update

    Returns:
        Updated project

    Raises:
        404: Project not found
        403: Insufficient permissions
        400: Duplicate name
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    project = _get_project_or_404(db, tenant_id, project_id)

    if updates.name is not None and updates.name != project.name:
        duplicate = (
            db.query(Project)
            .filter(
                Project.tenant_id == tenant_id,
                Project.name == updates.name,
                Project.id != project_id,
            )
            .first()
        )
        if duplicate:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with name '{updates.name}' already exists for this tenant",
            )
        project.name = updates.name

    if updates.description is not None:
        project.description = updates.description

    if updates.seeds is not None:
        project.seeds = updates.seeds

    if updates.settings is not None:
        project.settings = updates.settings

    db.commit()
    db.refresh(project)

    log_data_modification(
        action="update",
        resource="project",
        resource_id=str(project.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={k: v for k, v in updates.model_dump(exclude_unset=True).items() if k != "seeds"},
    )

    return ProjectResponse.model_validate(project)


@router.delete("/projects/{project_id}", response_model=SuccessResponse)
def delete_project(
    tenant_id: int,
    project_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Delete a project and all associated data.

    Removes scopes, scan profiles, scan runs (with their phase results,
    observations, and risk scores), and unlinks any issues.
    Projects with running or pending scans cannot be deleted.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)

    Returns:
        Success response

    Raises:
        404: Project not found
        403: Insufficient permissions
        400: Project has running/pending scans
    """
    if not membership.has_permission("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required",
        )

    project = _get_project_or_404(db, tenant_id, project_id)

    # Block deletion if there are running/pending scans
    active_scans = (
        db.query(ScanRun)
        .filter(
            ScanRun.project_id == project_id,
            ScanRun.status.in_([ScanRunStatus.PENDING, ScanRunStatus.RUNNING]),
        )
        .count()
    )
    if active_scans:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete project with running or pending scans. Cancel them first.",
        )

    # Clean up FK dependencies on scan runs before cascade deletes them
    from app.models.risk import RiskScore

    scan_run_ids = [r[0] for r in db.query(ScanRun.id).filter(ScanRun.project_id == project_id).all()]
    if scan_run_ids:
        db.query(RiskScore).filter(RiskScore.scan_run_id.in_(scan_run_ids)).delete(synchronize_session=False)
        db.query(PhaseResult).filter(PhaseResult.scan_run_id.in_(scan_run_ids)).delete(synchronize_session=False)
        db.query(Observation).filter(Observation.scan_run_id.in_(scan_run_ids)).delete(synchronize_session=False)
        db.flush()

    # Unlink issues (set project_id to NULL rather than deleting)
    from app.models.issues import Issue

    db.query(Issue).filter(Issue.project_id == project_id).update({"project_id": None}, synchronize_session=False)

    # Delete project (cascades to scopes, scan_profiles, scan_runs)
    project_name = project.name
    db.delete(project)
    db.commit()

    log_data_modification(
        action="delete",
        resource="project",
        resource_id=str(project_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"name": project_name},
    )

    logger.info(f"Deleted project {project_id} '{project_name}' (tenant {tenant_id})")

    return SuccessResponse(
        success=True,
        message=f"Project '{project_name}' deleted",
    )


# ===========================================================================
# SCOPE ENDPOINTS
# ===========================================================================


@router.post(
    "/projects/{project_id}/scopes",
    response_model=ScopeResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_scope_rule(
    tenant_id: int,
    project_id: int,
    scope_data: ScopeCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Add a scope rule (include or exclude) to a project.

    Scope rules define the boundaries for scanning targets.
    Exclude rules always take precedence over include rules.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        scope_data: Scope rule definition

    Returns:
        The created scope rule

    Raises:
        404: Project not found
        403: Insufficient permissions
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    project = _get_project_or_404(db, tenant_id, project_id)

    scope = Scope(
        project_id=project.id,
        rule_type=scope_data.rule_type,
        match_type=scope_data.match_type,
        pattern=scope_data.pattern,
        description=scope_data.description,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    logger.info(f"Added scope rule ({scope.rule_type}/{scope.match_type}: {scope.pattern}) to project {project.id}")

    return ScopeResponse.model_validate(scope)


@router.get("/projects/{project_id}/scopes", response_model=list[ScopeResponse])
def list_scopes(
    tenant_id: int,
    project_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List all scope rules for a project.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)

    Returns:
        List of scope rules ordered by creation date

    Raises:
        404: Project not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    scopes = (
        db.query(Scope)
        .filter(
            Scope.project_id == project_id,
        )
        .order_by(Scope.created_at.asc())
        .all()
    )

    return [ScopeResponse.model_validate(s) for s in scopes]


# ===========================================================================
# SCAN RUN ENDPOINTS
# ===========================================================================


@router.post("/projects/{project_id}/scans", response_model=TaskResponse)
def trigger_scan(
    tenant_id: int,
    project_id: int,
    trigger: ScanTrigger,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger a new scan run for a project.

    Creates a ScanRun record in PENDING status and dispatches the
    pipeline to Celery for asynchronous execution.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        trigger: Scan trigger configuration (optional profile_id, triggered_by)

    Returns:
        TaskResponse with Celery task ID and scan_run_id in data

    Raises:
        404: Project or profile not found
        403: Insufficient permissions
        400: Invalid profile_id
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    project = _get_project_or_404(db, tenant_id, project_id)

    # Validate profile if provided, otherwise auto-create from scan_tier
    profile_id = trigger.profile_id
    if profile_id is not None:
        profile = (
            db.query(ScanProfile)
            .filter(
                ScanProfile.id == profile_id,
                ScanProfile.project_id == project_id,
            )
            .first()
        )
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan profile {profile_id} not found for this project",
            )
    else:
        # Auto-create or find a default profile for the requested tier
        tier = trigger.scan_tier
        tier_names = {1: "Safe", 2: "Moderate", 3: "Aggressive"}
        tier_ports = {1: "top-100", 2: "top-1000", 3: "full"}
        tier_rates = {1: 10, 2: 50, 3: 100}
        tier_timeouts = {1: 60, 2: 120, 3: 240}
        default_name = f"Default {tier_names.get(tier, 'Safe')} (Tier {tier})"

        profile = (
            db.query(ScanProfile)
            .filter(
                ScanProfile.project_id == project_id,
                ScanProfile.name == default_name,
            )
            .first()
        )

        if not profile:
            profile = ScanProfile(
                project_id=project.id,
                name=default_name,
                scan_tier=tier,
                port_scan_mode=tier_ports.get(tier, "top-100"),
                max_rate_pps=tier_rates.get(tier, 10),
                timeout_minutes=tier_timeouts.get(tier, 120),
            )
            db.add(profile)
            db.flush()

        profile_id = profile.id

    # Create scan run
    scan_run = ScanRun(
        project_id=project.id,
        profile_id=profile_id,
        tenant_id=tenant_id,
        status=ScanRunStatus.PENDING,
        triggered_by=trigger.triggered_by,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    # Dispatch to Celery
    from app.tasks.pipeline import run_scan_pipeline

    task = run_scan_pipeline.delay(scan_run.id)

    # Store celery task id
    scan_run.celery_task_id = task.id
    db.commit()

    logger.info(
        f"Triggered scan run {scan_run.id} for project '{project.name}' "
        f"(tenant={tenant_id}, trigger={trigger.triggered_by})"
    )

    return TaskResponse(
        task_id=task.id,
        status="queued",
        message=f"Scan queued for project '{project.name}'",
        data={"scan_run_id": scan_run.id},
    )


@router.get("/projects/{project_id}/scans", response_model=PaginatedResponse[ScanRunResponse])
def list_scan_runs(
    tenant_id: int,
    project_id: int,
    scan_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List scan runs for a project with optional status filter and pagination.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        scan_status: Optional status filter (pending, running, completed, failed, cancelled)
        pagination: Standard pagination parameters

    Returns:
        Paginated list of scan runs ordered by creation date descending

    Raises:
        404: Project not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    query = db.query(ScanRun).filter(
        ScanRun.project_id == project_id,
        ScanRun.tenant_id == tenant_id,
    )

    if scan_status:
        try:
            status_enum = ScanRunStatus(scan_status)
            query = query.filter(ScanRun.status == status_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan status: {scan_status}",
            )

    total = query.count()
    query = query.order_by(ScanRun.created_at.desc())
    query = pagination.paginate_query(query)
    runs = query.all()

    items = [_serialize_scan_run(r) for r in runs]

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size if total else 0,
    )


@router.get("/projects/{project_id}/scans/{run_id}/progress", response_model=ScanProgressResponse)
def get_scan_progress(
    tenant_id: int,
    project_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get real-time progress for a scan run.

    Returns the scan run status plus all per-phase results, enabling
    a UI to render a progress bar or phase-by-phase dashboard.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        run_id: Scan run ID (path)

    Returns:
        Scan run with all phase results

    Raises:
        404: Project or scan run not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.project_id == project_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    phases = (
        db.query(PhaseResult)
        .filter(
            PhaseResult.scan_run_id == run_id,
        )
        .order_by(PhaseResult.phase.asc())
        .all()
    )

    return ScanProgressResponse(
        scan_run=_serialize_scan_run(scan_run),
        phases=[_serialize_phase_result(p) for p in phases],
    )


@router.get("/projects/{project_id}/scans/{run_id}/changes", response_model=list[ChangeEventResponse])
def get_scan_changes(
    tenant_id: int,
    project_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get change events produced by a scan run.

    Extracts change information from phase stats and observations
    collected during the scan. Useful for diffing against previous runs.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        run_id: Scan run ID (path)

    Returns:
        List of change events

    Raises:
        404: Project or scan run not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.project_id == project_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    changes: list[dict] = []

    # Extract change events from scan run stats
    run_stats = scan_run.stats or {}
    for change_event in run_stats.get("change_events", []):
        changes.append(
            ChangeEventResponse(
                phase="aggregate",
                event_type=change_event.get("type", "unknown"),
                detail=change_event,
            )
        )

    # Extract change events from phase results
    phases = (
        db.query(PhaseResult)
        .filter(
            PhaseResult.scan_run_id == run_id,
        )
        .all()
    )

    for phase in phases:
        phase_stats = phase.stats or {}

        if phase_stats.get("assets_discovered", 0) > 0:
            changes.append(
                ChangeEventResponse(
                    phase=phase.phase,
                    event_type="new_assets",
                    detail={"count": phase_stats["assets_discovered"]},
                )
            )

        if phase_stats.get("findings_created", 0) > 0:
            changes.append(
                ChangeEventResponse(
                    phase=phase.phase,
                    event_type="new_findings",
                    detail={"count": phase_stats["findings_created"]},
                )
            )

        if phase_stats.get("ports_discovered", 0) > 0:
            changes.append(
                ChangeEventResponse(
                    phase=phase.phase,
                    event_type="new_ports",
                    detail={"count": phase_stats["ports_discovered"]},
                )
            )

        if phase_stats.get("services_discovered", 0) > 0:
            changes.append(
                ChangeEventResponse(
                    phase=phase.phase,
                    event_type="new_services",
                    detail={"count": phase_stats["services_discovered"]},
                )
            )

        if phase_stats.get("endpoints_discovered", 0) > 0:
            changes.append(
                ChangeEventResponse(
                    phase=phase.phase,
                    event_type="new_endpoints",
                    detail={"count": phase_stats["endpoints_discovered"]},
                )
            )

    # Include observations summary
    observation_count = (
        db.query(func.count(Observation.id))
        .filter(
            Observation.scan_run_id == run_id,
        )
        .scalar()
        or 0
    )

    if observation_count > 0:
        changes.append(
            ChangeEventResponse(
                phase="all",
                event_type="observations_collected",
                detail={"count": observation_count},
            )
        )

    return changes


@router.post("/projects/{project_id}/scans/{run_id}/cancel", response_model=SuccessResponse)
def cancel_scan_run(
    tenant_id: int,
    project_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Cancel a running scan.

    Dispatches a cancel task to Celery that will revoke the running
    pipeline and mark the scan run as CANCELLED.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        run_id: Scan run ID (path)

    Returns:
        Success response

    Raises:
        404: Project or scan run not found
        403: Insufficient permissions
        400: Scan is not in a cancellable state
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    _get_project_or_404(db, tenant_id, project_id)

    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.project_id == project_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    if scan_run.status not in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in status '{scan_run.status.value}'",
        )

    from app.tasks.pipeline import cancel_scan

    cancel_scan.delay(scan_run.id)

    logger.info(f"Cancellation requested for scan run {run_id} (project {project_id})")

    return SuccessResponse(
        success=True,
        message=f"Cancellation requested for scan run {run_id}",
    )


# ===========================================================================
# SCAN PROFILE ENDPOINTS
# ===========================================================================


@router.get("/projects/{project_id}/profiles", response_model=list[ScanProfileResponse])
def list_profiles(
    tenant_id: int,
    project_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List all scan profiles for a project.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)

    Returns:
        List of scan profiles ordered by creation date

    Raises:
        404: Project not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    profiles = (
        db.query(ScanProfile)
        .filter(
            ScanProfile.project_id == project_id,
        )
        .order_by(ScanProfile.created_at.asc())
        .all()
    )

    return [ScanProfileResponse.model_validate(p) for p in profiles]


@router.post(
    "/projects/{project_id}/profiles",
    response_model=ScanProfileResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_profile(
    tenant_id: int,
    project_id: int,
    profile_data: ScanProfileCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Create a new scan profile for a project.

    Scan profiles define execution parameters like scan tier, port scan
    mode, Nuclei template tags, rate limits, and optional cron scheduling.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        profile_data: Scan profile configuration

    Returns:
        The created scan profile

    Raises:
        404: Project not found
        403: Insufficient permissions
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    project = _get_project_or_404(db, tenant_id, project_id)

    profile = ScanProfile(
        project_id=project.id,
        name=profile_data.name,
        scan_tier=profile_data.scan_tier,
        port_scan_mode=profile_data.port_scan_mode,
        nuclei_tags=profile_data.nuclei_tags,
        schedule_cron=profile_data.schedule_cron,
        max_rate_pps=profile_data.max_rate_pps,
        timeout_minutes=profile_data.timeout_minutes,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    logger.info(f"Created scan profile '{profile.name}' (id={profile.id}) for project {project.id}")

    return ScanProfileResponse.model_validate(profile)


@router.patch(
    "/projects/{project_id}/profiles/{profile_id}/schedule",
    response_model=ScanProfileResponse,
)
def update_profile_schedule(
    tenant_id: int,
    project_id: int,
    profile_id: int,
    schedule: ScheduleUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Set or clear the cron schedule for a scan profile.

    Pass a cron expression to enable scheduling, or null to disable it.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)
        profile_id: Scan profile ID (path)
        schedule: Schedule update payload

    Returns:
        Updated scan profile

    Raises:
        404: Project or profile not found
        403: Insufficient permissions
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    _get_project_or_404(db, tenant_id, project_id)

    profile = (
        db.query(ScanProfile)
        .filter(
            ScanProfile.id == profile_id,
            ScanProfile.project_id == project_id,
        )
        .first()
    )
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan profile not found",
        )

    profile.schedule_cron = schedule.schedule_cron
    db.commit()
    db.refresh(profile)

    action = "set" if schedule.schedule_cron else "cleared"
    logger.info(f"Schedule {action} for profile {profile_id} (cron={schedule.schedule_cron})")

    return ScanProfileResponse.model_validate(profile)


# ===========================================================================
# MONITORING STATUS
# ===========================================================================


@router.get("/projects/{project_id}/monitoring-status", response_model=MonitoringStatusResponse)
def get_monitoring_status(
    tenant_id: int,
    project_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get the monitoring status for a project.

    Provides a summary of active and scheduled profiles, running scans,
    and the last completed scan run for quick dashboard rendering.

    Args:
        tenant_id: Tenant ID (path)
        project_id: Project ID (path)

    Returns:
        Monitoring status overview

    Raises:
        404: Project not found
    """
    _get_project_or_404(db, tenant_id, project_id)

    # Count active profiles
    active_profiles = (
        db.query(func.count(ScanProfile.id))
        .filter(
            ScanProfile.project_id == project_id,
            ScanProfile.enabled == True,
        )
        .scalar()
        or 0
    )

    # Count scheduled profiles (have a cron expression)
    scheduled_profiles = (
        db.query(func.count(ScanProfile.id))
        .filter(
            ScanProfile.project_id == project_id,
            ScanProfile.enabled == True,
            ScanProfile.schedule_cron.isnot(None),
        )
        .scalar()
        or 0
    )

    # Count running scans
    running_scans = (
        db.query(func.count(ScanRun.id))
        .filter(
            ScanRun.project_id == project_id,
            ScanRun.tenant_id == tenant_id,
            ScanRun.status.in_([ScanRunStatus.PENDING, ScanRunStatus.RUNNING]),
        )
        .scalar()
        or 0
    )

    # Last completed scan
    last_completed = (
        db.query(ScanRun)
        .filter(
            ScanRun.project_id == project_id,
            ScanRun.tenant_id == tenant_id,
            ScanRun.status == ScanRunStatus.COMPLETED,
        )
        .order_by(ScanRun.completed_at.desc())
        .first()
    )

    # Next scheduled profile (first enabled profile with a cron expression)
    next_scheduled = (
        db.query(ScanProfile)
        .filter(
            ScanProfile.project_id == project_id,
            ScanProfile.enabled == True,
            ScanProfile.schedule_cron.isnot(None),
        )
        .order_by(ScanProfile.created_at.asc())
        .first()
    )

    return MonitoringStatusResponse(
        project_id=project_id,
        active_profiles=active_profiles,
        scheduled_profiles=scheduled_profiles,
        running_scans=running_scans,
        last_completed_scan=_serialize_scan_run(last_completed) if last_completed else None,
        next_scheduled_profile=(ScanProfileResponse.model_validate(next_scheduled) if next_scheduled else None),
    )


# ===========================================================================
# CONVENIENCE SCAN RUN ENDPOINTS (by run ID, no project_id needed)
# ===========================================================================


@router.get("/scans/{run_id}", response_model=ScanRunResponse)
def get_scan_run_by_id(
    tenant_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Get a scan run by its ID (scoped to tenant)."""
    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )
    return _serialize_scan_run(scan_run)


@router.get("/scans/{run_id}/progress", response_model=ScanProgressResponse)
def get_scan_run_progress_by_id(
    tenant_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Get scan run progress by run ID (scoped to tenant)."""
    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    phases = (
        db.query(PhaseResult)
        .filter(
            PhaseResult.scan_run_id == run_id,
        )
        .order_by(PhaseResult.phase.asc())
        .all()
    )

    return ScanProgressResponse(
        scan_run=_serialize_scan_run(scan_run),
        phases=[_serialize_phase_result(p) for p in phases],
    )


@router.delete("/scans/{run_id}", response_model=SuccessResponse)
def delete_scan_run_by_id(
    tenant_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Delete a scan run and its phase results (scoped to tenant).

    Only completed, failed, or cancelled scans can be deleted.
    Running/pending scans must be cancelled first.
    """
    if not membership.has_permission("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required",
        )

    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    if scan_run.status in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running or pending scan. Cancel it first.",
        )

    # Delete dependent records first (FK constraints).
    # Use synchronize_session=False to avoid session evaluation issues
    # and flush to ensure SQL executes before the scan_run delete.
    from app.models.risk import RiskScore

    db.query(RiskScore).filter(RiskScore.scan_run_id == run_id).delete(synchronize_session=False)
    db.query(PhaseResult).filter(PhaseResult.scan_run_id == run_id).delete(synchronize_session=False)
    db.query(Observation).filter(Observation.scan_run_id == run_id).delete(synchronize_session=False)
    db.flush()
    db.delete(scan_run)
    db.commit()

    logger.info(f"Deleted scan run {run_id} (tenant {tenant_id})")

    return SuccessResponse(
        success=True,
        message=f"Scan run {run_id} deleted",
    )


@router.post("/scans/{run_id}/cancel", response_model=SuccessResponse)
def cancel_scan_run_by_id(
    tenant_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Cancel a scan run by its ID (scoped to tenant)."""
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    scan_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.id == run_id,
            ScanRun.tenant_id == tenant_id,
        )
        .first()
    )
    if not scan_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    if scan_run.status not in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in status '{scan_run.status.value}'",
        )

    from app.tasks.pipeline import cancel_scan

    cancel_scan.delay(scan_run.id)

    return SuccessResponse(
        success=True,
        message=f"Cancellation requested for scan run {run_id}",
    )
