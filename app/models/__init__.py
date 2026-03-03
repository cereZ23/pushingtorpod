"""
Models package - imports all models to ensure they are registered with SQLAlchemy
"""

# Import Base first
from app.models.database import Base

# Import all models to register them with SQLAlchemy
from app.models.database import (
    Tenant,
    Asset,
    AssetType,
    Service,
    Finding,
    FindingStatus,
    FindingSeverity,
    Event,
    EventKind,
    Seed,
)

from app.models.auth import (
    User,
    TenantMembership,
    APIKey,
    UserInvitation,
)

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

from app.models.issues import (
    Issue,
    IssueStatus,
    IssueFinding,
    IssueActivity,
)

from app.models.risk import (
    RiskScore,
    Alert,
    AlertStatus,
    AlertPolicy,
    Relationship,
    AuditLog,
)

from app.models.ticketing import (
    TicketingConfig,
    Ticket,
)

from app.models.report_schedule import (
    ReportSchedule,
)

__all__ = [
    'Base',
    'Tenant',
    'Asset',
    'AssetType',
    'Service',
    'Finding',
    'FindingStatus',
    'FindingSeverity',
    'Event',
    'EventKind',
    'Seed',
    'User',
    'TenantMembership',
    'APIKey',
    'Project',
    'Scope',
    'ScanProfile',
    'ScanRun',
    'ScanRunStatus',
    'PhaseResult',
    'PhaseStatus',
    'Observation',
    'Issue',
    'IssueStatus',
    'IssueFinding',
    'IssueActivity',
    'RiskScore',
    'Alert',
    'AlertStatus',
    'AlertPolicy',
    'Relationship',
    'Ticket',
    'AuditLog',
    'TicketingConfig',
    'ReportSchedule',
    'UserInvitation',
]
