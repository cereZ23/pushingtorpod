"""Scan authorization — the record that a tenant is permitted to scan a scope.

Active scanning is legally sensitive: probing a target we are not authorized to
touch is an incident, not a bug. This model makes authorization explicit and
enforceable (see app.services.scope_authorization): a scan target must fall
within an active, in-window ScanAuthorization's scope.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import relationship

from app.models.database import Base


class ScanAuthorization(Base):
    __tablename__ = "scan_authorizations"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)

    # List of {"type": "domain"|"ip"|"cidr", "value": "..."} the scan may touch.
    scope_entries = Column(JSON, nullable=False, default=list)

    authorized_by = Column(String(255))  # who signed off (name/email/ref)
    authorization_ref = Column(String(500))  # signed doc / ticket / engagement ref
    authorized_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    valid_from = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    valid_until = Column(DateTime, nullable=True)  # NULL = open-ended
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant")

    __table_args__ = (Index("idx_scan_auth_tenant_active", "tenant_id", "is_active"),)

    def __repr__(self) -> str:
        return f"<ScanAuthorization(id={self.id}, tenant_id={self.tenant_id}, name='{self.name}')>"
