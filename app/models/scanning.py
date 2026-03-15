"""
Scan management models for the EASM platform

Provides models for organizing and tracking scan operations:
- Project: Organizational unit grouping seeds, scopes, and scan profiles
- Scope: Include/exclude rules for target validation
- ScanProfile: Reusable scan configuration with scheduling
- ScanRun: Individual scan execution records with status tracking
- PhaseResult: Per-phase progress tracking within a scan run
- Observation: Intermediate discovery artifacts from reconnaissance tools

These models support the full scan lifecycle from configuration through
execution, tracking, and artifact collection.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Text,
    Enum,
    Boolean,
    Index,
    JSON,
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from app.models.database import Base


class ScanRunStatus(enum.Enum):
    """Status values for scan run lifecycle"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PhaseStatus(enum.Enum):
    """Status values for individual scan phases"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Project(Base):
    """
    Scan organizational unit grouping seeds, scopes, and profiles

    A Project represents a logical scanning target (e.g., a client engagement
    or a specific attack surface boundary). It holds seed values, scope rules,
    and one or more scan profiles that define how scans are executed.

    Attributes:
        tenant_id: Owning tenant for multi-tenant isolation
        name: Human-readable project name (unique per tenant)
        description: Optional detailed description
        seeds: JSON list of seed values [{"type": "domain", "value": "example.com"}]
        settings: JSON project-level settings overrides
        created_by: User who created the project

    Relationships:
        - Belongs to one Tenant (many-to-one)
        - Created by one User (many-to-one)
        - Has many Scopes (one-to-many)
        - Has many ScanProfiles (one-to-many)
        - Has many ScanRuns (one-to-many)
    """

    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    seeds = Column(JSON)  # [{"type": "domain", "value": "example.com"}, ...]
    settings = Column(JSON)  # Project-level settings overrides
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    tenant = relationship("Tenant", backref="projects")
    creator = relationship("User", backref="created_projects", foreign_keys=[created_by])
    scopes = relationship("Scope", back_populates="project", cascade="all, delete-orphan")
    scan_profiles = relationship("ScanProfile", back_populates="project", cascade="all, delete-orphan")
    scan_runs = relationship("ScanRun", back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_project_tenant", "tenant_id"),
        Index("idx_project_tenant_name", "tenant_id", "name", unique=True),
    )

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}', tenant_id={self.tenant_id})>"


class Scope(Base):
    """
    Include/exclude rules for scan scope validation

    Defines boundaries for what targets are in-scope or explicitly excluded
    from scanning. Rules are evaluated in order; exclude rules take precedence
    to prevent scanning out-of-scope targets.

    Attributes:
        project_id: Parent project
        rule_type: 'include' or 'exclude'
        match_type: How the pattern is matched ('domain', 'ip', 'cidr', 'regex')
        pattern: The pattern string (e.g., "*.example.com", "10.0.0.0/8")
        description: Optional human-readable explanation of the rule

    Relationships:
        - Belongs to one Project (many-to-one)
    """

    __tablename__ = "scopes"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    rule_type = Column(String(20), nullable=False)  # 'include' or 'exclude'
    match_type = Column(String(20), nullable=False)  # 'domain', 'ip', 'cidr', 'regex'
    pattern = Column(String(500), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", back_populates="scopes")

    __table_args__ = (Index("idx_scope_project", "project_id"),)

    def __repr__(self):
        return f"<Scope(id={self.id}, rule_type='{self.rule_type}', pattern='{self.pattern}')>"


class ScanProfile(Base):
    """
    Reusable scan configuration with optional scheduling

    Defines how a scan is executed: which tools run, at what intensity,
    and on what schedule. Multiple profiles per project allow different
    scan tiers (e.g., daily light scan vs. weekly deep scan).

    Attributes:
        project_id: Parent project
        name: Human-readable profile name
        scan_tier: Aggressiveness level (1=Safe, 2=Moderate, 3=Aggressive)
        port_scan_mode: Port scanning strategy ('top-100', 'top-1000', 'full')
        nuclei_tags: JSON list of Nuclei template tags ["cves", "exposed-panels"]
        schedule_cron: Cron expression for automatic scheduling, null for manual
        max_rate_pps: Maximum packets per second for rate limiting
        timeout_minutes: Maximum scan duration before timeout
        enabled: Whether scheduled scans are active

    Relationships:
        - Belongs to one Project (many-to-one)
        - Has many ScanRuns (one-to-many)
    """

    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    scan_tier = Column(Integer, default=1)  # 1=Safe, 2=Moderate, 3=Aggressive
    port_scan_mode = Column(String(50), default="top-100")
    nuclei_tags = Column(JSON)  # ["cves", "exposed-panels", "misconfiguration"]
    schedule_cron = Column(String(100))  # Cron expression or null for manual
    max_rate_pps = Column(Integer, default=10)
    timeout_minutes = Column(Integer, default=120)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    project = relationship("Project", back_populates="scan_profiles")
    scan_runs = relationship("ScanRun", back_populates="profile")

    __table_args__ = (
        Index("idx_profile_project", "project_id"),
        Index("idx_profile_project_enabled", "project_id", "enabled"),
    )

    def __repr__(self):
        return f"<ScanProfile(id={self.id}, name='{self.name}', tier={self.scan_tier})>"


class ScanRun(Base):
    """
    Individual scan execution record

    Tracks the full lifecycle of a single scan execution from creation
    through completion or failure. Links to the project and optionally
    to a scan profile. Stores aggregate statistics and Celery task ID
    for cancellation support.

    Attributes:
        project_id: Parent project
        profile_id: Optional scan profile used for this run
        tenant_id: Owning tenant (denormalized for efficient querying)
        status: Current execution status
        triggered_by: How the scan was initiated ('manual', 'schedule', 'api')
        started_at: When execution began
        completed_at: When execution finished
        stats: JSON aggregate stats {phases, asset_count, finding_count, change_events}
        error_message: Error details if status is FAILED
        celery_task_id: Celery task ID for tracking and cancellation

    Relationships:
        - Belongs to one Project (many-to-one)
        - Belongs to one ScanProfile (many-to-one, optional)
        - Belongs to one Tenant (many-to-one)
        - Has many PhaseResults (one-to-many)
        - Has many Observations (one-to-many)
    """

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"))
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    status = Column(
        Enum(
            ScanRunStatus,
            values_callable=lambda x: [e.value for e in x],
            native_enum=False,
            create_constraint=False,
        ),
        default=ScanRunStatus.PENDING,
    )
    triggered_by = Column(String(100))  # 'manual', 'schedule', 'api'
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    stats = Column(JSON)  # {phases: {...}, asset_count, finding_count, change_events: [...]}
    error_message = Column(Text)
    celery_task_id = Column(String(255))  # For tracking/cancellation
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", back_populates="scan_runs")
    profile = relationship("ScanProfile", back_populates="scan_runs")
    tenant = relationship("Tenant", backref="scan_runs")
    phase_results = relationship("PhaseResult", back_populates="scan_run", cascade="all, delete-orphan")
    observations = relationship("Observation", back_populates="scan_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scanrun_project", "project_id"),
        Index("idx_scanrun_tenant", "tenant_id"),
        Index("idx_scanrun_status", "status"),
        Index("idx_scanrun_project_created", "project_id", "created_at"),
    )

    def __repr__(self):
        return f"<ScanRun(id={self.id}, project_id={self.project_id}, status={self.status.value})>"

    @property
    def duration_seconds(self) -> int | None:
        """Calculate scan duration in seconds, or None if not yet completed"""
        if not self.started_at or not self.completed_at:
            return None
        return int((self.completed_at - self.started_at).total_seconds())


class PhaseResult(Base):
    """
    Per-phase tracking within a scan run

    Each scan run consists of multiple phases (discovery, enrichment,
    scanning, etc.). This model tracks the status and statistics of
    each phase independently, enabling fine-grained progress monitoring
    and failure isolation.

    Attributes:
        scan_run_id: Parent scan run
        phase: Phase identifier ('0', '1', '1b', '1c', '2', etc.)
        status: Current phase status
        started_at: When this phase began
        completed_at: When this phase finished
        stats: JSON phase-specific stats {items_found, items_processed, errors, etc.}
        error_message: Error details if phase failed

    Relationships:
        - Belongs to one ScanRun (many-to-one)
    """

    __tablename__ = "phase_results"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    phase = Column(String(10), nullable=False)  # '0', '1', '1b', '1c', '2', etc.
    status = Column(
        Enum(
            PhaseStatus,
            values_callable=lambda x: [e.value for e in x],
            native_enum=False,
            create_constraint=False,
        ),
        default=PhaseStatus.PENDING,
    )
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    stats = Column(JSON)  # Phase-specific stats {items_found, items_processed, etc.}
    error_message = Column(Text)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="phase_results")

    __table_args__ = (
        Index("idx_phase_scanrun", "scan_run_id"),
        Index("idx_phase_scanrun_phase", "scan_run_id", "phase", unique=True),
    )

    def __repr__(self):
        return f"<PhaseResult(id={self.id}, phase='{self.phase}', status={self.status.value})>"

    @property
    def duration_seconds(self) -> int | None:
        """Calculate phase duration in seconds, or None if not yet completed"""
        if not self.started_at or not self.completed_at:
            return None
        return int((self.completed_at - self.started_at).total_seconds())


class Observation(Base):
    """
    Intermediate discovery artifacts from reconnaissance tools

    Stores raw observations collected during scan phases before they are
    normalized into Assets, Services, or Findings. This preserves the
    original data from each tool (subfinder, crtsh, dnsx, etc.) for
    audit trails and re-processing.

    Attributes:
        tenant_id: Owning tenant for multi-tenant isolation
        scan_run_id: Parent scan run (optional for manual imports)
        asset_id: Linked asset if observation has been correlated
        source: Tool that produced this observation ('subfinder', 'crtsh', 'dnsx', etc.)
        observation_type: Classification ('passive_subdomain', 'spf_ip', 'mx_ip', etc.)
        raw_data: JSON raw tool output for this observation
        created_at: When the observation was recorded

    Relationships:
        - Belongs to one Tenant (many-to-one)
        - Belongs to one ScanRun (many-to-one, optional)
        - Belongs to one Asset (many-to-one, optional)
    """

    __tablename__ = "observations"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="SET NULL"))
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"))
    source = Column(String(100), nullable=False)  # 'subfinder', 'crtsh', 'dnsx', etc.
    observation_type = Column(String(100), nullable=False)  # 'passive_subdomain', 'spf_ip', 'mx_ip'
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    tenant = relationship("Tenant", backref="observations")
    scan_run = relationship("ScanRun", back_populates="observations")
    asset = relationship("Asset", backref="observations")

    __table_args__ = (
        Index("idx_observation_tenant", "tenant_id"),
        Index("idx_observation_scanrun", "scan_run_id"),
        Index("idx_observation_type", "observation_type"),
    )

    def __repr__(self):
        return f"<Observation(id={self.id}, source='{self.source}', type='{self.observation_type}')>"
