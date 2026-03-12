"""
Ticketing integration models

Provides database models for external ticket system integration:
- TicketingConfig: Per-tenant configuration for Jira/ServiceNow
- Ticket: Individual ticket records linked to EASM issues (findings)

Security:
- API tokens and credentials are stored AES-encrypted
- Encryption key derived from settings.secret_key
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text, Boolean, Index, JSON
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from app.models.database import Base


class TicketProvider(enum.Enum):
    JIRA = "jira"
    SERVICENOW = "servicenow"


class TicketSyncStatus(enum.Enum):
    SYNCED = "synced"
    PENDING = "pending"
    ERROR = "error"
    CONFLICT = "conflict"


class TicketingConfig(Base):
    """
    Per-tenant ticketing integration configuration.

    Stores encrypted credentials for Jira or ServiceNow.
    Only one active config per tenant is allowed.
    """
    __tablename__ = 'ticketing_configs'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    provider = Column(String(50), nullable=False)  # 'jira', 'servicenow'
    config_encrypted = Column(Text, nullable=False)  # AES-encrypted JSON config
    is_active = Column(Boolean, default=True, nullable=False)
    auto_create_on_triage = Column(Boolean, default=False, nullable=False)
    sync_status_back = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_ticketing_config_tenant', 'tenant_id'),
        Index('idx_ticketing_config_active', 'tenant_id', 'is_active'),
    )

    def __repr__(self):
        return (
            f"<TicketingConfig(id={self.id}, tenant_id={self.tenant_id}, "
            f"provider='{self.provider}', is_active={self.is_active})>"
        )


class Ticket(Base):
    """
    Individual ticket record linking an EASM finding to an external ticket.

    Tracks bi-directional sync state between the EASM platform and
    the external ticketing system (Jira or ServiceNow).
    """
    __tablename__ = 'tickets'

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False)
    provider = Column(String(50), nullable=False)  # 'jira', 'servicenow'
    external_id = Column(String(255), nullable=False)  # e.g., "EASM-123" or "INC0012345"
    external_url = Column(String(2048))
    external_status = Column(String(100))  # e.g., "To Do", "In Progress", "Done"
    sync_status = Column(String(50), default='synced')  # synced, pending, error, conflict
    sync_error = Column(Text)  # Last sync error message
    last_synced_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Extra metadata for the external ticket
    external_metadata = Column(JSON)  # Assignee, labels, priority, etc.

    finding = relationship("Finding", backref="tickets")

    __table_args__ = (
        Index('idx_ticket_tenant', 'tenant_id'),
        Index('idx_ticket_finding', 'finding_id'),
        Index('idx_ticket_external_id', 'external_id'),
        Index('idx_ticket_sync_status', 'sync_status'),
        Index('idx_ticket_tenant_provider', 'tenant_id', 'provider'),
    )

    def __repr__(self):
        return (
            f"<Ticket(id={self.id}, finding_id={self.finding_id}, "
            f"provider='{self.provider}', external_id='{self.external_id}')>"
        )
