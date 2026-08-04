"""Coverage-ledger models — the persistent side of the scan-policy / rule-catalog foundation.

Three tables turn the pure services ([[scan_policy]], [[rule_revision]],
[[rule_catalog]]) into a durable record that a coverage-aware auto-close can trust:

- ``scan_policy``           — the immutable identity of what a pass executes, keyed by
                              ``policy_hash`` (GLOBAL: the hash is content-derived and
                              tenant-independent, so identical policies dedupe).
- ``scan_policy_templates`` — the applicable detector catalog for a policy (also global,
                              FK → scan_policy). One row per (policy_hash, detector_id).
- ``scan_coverage``         — per (run, pass, asset) coverage status (TENANT-scoped,
                              under RLS). Conservative to start: a whole pass is declared
                              covered / partial / failed / skipped for all its assets.

Auto-close (later) is the intersection: a finding on asset A from detector D in pass P
may be closed only if ``scan_coverage`` has a COVERED row for (run, P, A) AND D is in
``scan_policy_templates`` for that pass's policy.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.models.database import Base


class CoverageStatus(enum.Enum):
    """Per (run, pass, asset) coverage outcome. Stored as VARCHAR (native_enum=False)."""

    COVERED = "covered"  # pass ran to completion over this asset
    PARTIAL = "partial"  # pass ran but did not fully cover (e.g. nuclei truncated)
    FAILED = "failed"  # pass raised for this asset
    SKIPPED = "skipped"  # pass did not run (informational, not authorising)
    UNSTARTED = "unstarted"  # planned but never reached


def _coverage_status_enum() -> Enum:
    return Enum(
        CoverageStatus,
        values_callable=lambda x: [e.value for e in x],
        native_enum=False,
        create_constraint=False,
    )


class ScanPolicy(Base):
    """Immutable identity of what a scan pass executes (global, keyed by policy_hash).

    Written insert-if-absent and NEVER updated — a changed input yields a different
    ``policy_hash`` and thus a new row. Mirrors the pure ``ScanPolicyManifest``.
    """

    __tablename__ = "scan_policy"

    policy_hash = Column(String(64), primary_key=True)
    schema_version = Column(String(16), nullable=False)
    engine_name = Column(String(32), nullable=False)
    engine_version = Column(String(128), nullable=False)
    rule_revision = Column(String(64), nullable=False)
    phase = Column(String(10), nullable=False)
    pass_name = Column(String(64), nullable=False)
    tier = Column(Integer, nullable=False)
    severity = Column(JSON, nullable=False)  # sorted list
    rule_roots = Column(JSON, nullable=False)  # sorted list
    exclude_tags = Column(JSON, nullable=False)  # sorted list
    relevant_flags = Column(JSON, nullable=False)  # sorted {k: v}
    # Optional identity refinements (Sprint 3, migration 029): when the applicable set is a CLASSIFIED
    # subset (the http_endpoint pass), the derived catalog digest + classifier version are part of
    # policy_hash, so they are persisted here too — the stored row must mirror the FULL manifest.
    # NULL for every other pass (their identity is unchanged).
    catalog_digest = Column(String(64), nullable=True)
    classifier_version = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    templates = relationship("ScanPolicyTemplate", back_populates="policy", cascade="all, delete-orphan")

    __table_args__ = (
        # target for scan_coverage's composite FK — ties a coverage row to the policy's
        # own (phase, pass_name) so a semantically-false pairing is impossible even from
        # raw SQL. (policy_hash is already the PK; this unique exists to anchor the FK.)
        UniqueConstraint("policy_hash", "phase", "pass_name", name="uq_policy_phase_pass"),
        Index("idx_scan_policy_pass", "engine_name", "pass_name"),
    )

    def __repr__(self) -> str:
        return f"<ScanPolicy(policy_hash={self.policy_hash[:12]}…, pass={self.pass_name!r})>"


class ScanPolicyTemplate(Base):
    """One applicable detector for a policy (global; the persisted rule catalog)."""

    __tablename__ = "scan_policy_templates"

    id = Column(Integer, primary_key=True)
    policy_hash = Column(String(64), ForeignKey("scan_policy.policy_hash", ondelete="CASCADE"), nullable=False)
    detector_id = Column(String(255), nullable=False)  # nuclei template id / misconfig control id
    relative_path = Column(String(1024), nullable=False)
    content_digest = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=True)
    tags = Column(JSON, nullable=False, default=list)  # sorted list

    policy = relationship("ScanPolicy", back_populates="templates")

    __table_args__ = (
        UniqueConstraint("policy_hash", "detector_id", name="uq_policy_template"),
        Index("idx_policy_template_policy", "policy_hash"),
        Index("idx_policy_template_detector", "detector_id"),
    )

    def __repr__(self) -> str:
        return f"<ScanPolicyTemplate(policy={self.policy_hash[:12]}…, detector={self.detector_id!r})>"


class ScanPolicyCatalog(Base):
    """Proof that a policy's applicable-detector catalog was FULLY built, + its fingerprint.

    Written atomically with ``scan_policy_templates`` (same transaction) so its presence
    means the catalog was persisted and verified in full. The emit checks the live rows'
    ``(detector_count, catalog_digest)`` against this row before skipping re-enumeration —
    so a partial or tampered catalog (e.g. an extra, non-applicable detector) is never
    mistaken for complete. Global 1:1 companion to ``scan_policy``.
    """

    __tablename__ = "scan_policy_catalog"

    policy_hash = Column(String(64), ForeignKey("scan_policy.policy_hash", ondelete="CASCADE"), primary_key=True)
    detector_count = Column(Integer, nullable=False)
    catalog_digest = Column(String(64), nullable=False)
    built_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self) -> str:
        return f"<ScanPolicyCatalog(policy={self.policy_hash[:12]}…, n={self.detector_count})>"


class ScanCoverage(Base):
    """Per (run, pass, asset) coverage status — tenant-scoped, under RLS.

    ``policy_hash`` ties the row to the applicable catalog in ``scan_policy_templates``
    so auto-close can be per-detector. Unique on (scan_run_id, phase, pass_name,
    asset_id): one verdict per asset per pass per run, updated idempotently.
    """

    __tablename__ = "scan_coverage"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    phase = Column(String(10), nullable=False)
    pass_name = Column(String(64), nullable=False)
    policy_hash = Column(String(64), nullable=False)  # composite FK below → (policy_hash, phase, pass_name)
    status = Column(_coverage_status_enum(), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("scan_run_id", "phase", "pass_name", "asset_id", name="uq_coverage_run_pass_asset"),
        # composite FK: the coverage's (policy_hash, phase, pass_name) MUST match the
        # policy's own — no coverage can name a policy for a different phase/pass.
        ForeignKeyConstraint(
            ["policy_hash", "phase", "pass_name"],
            ["scan_policy.policy_hash", "scan_policy.phase", "scan_policy.pass_name"],
            name="fk_coverage_policy_phase_pass",
        ),
        CheckConstraint(
            "status IN ('covered', 'partial', 'failed', 'skipped', 'unstarted')", name="ck_coverage_status"
        ),
        Index("idx_coverage_tenant_asset_pass", "tenant_id", "asset_id", "pass_name", "created_at"),
        Index("idx_coverage_run", "scan_run_id"),
        Index("idx_coverage_policy", "policy_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanCoverage(run={self.scan_run_id}, pass={self.pass_name!r}, "
            f"asset={self.asset_id}, status={self.status.value if self.status else None})>"
        )


class ScanEndpointCoverage(Base):
    """Per (run, pass, asset, endpoint_shape) coverage status — tenant-scoped, under RLS (Sprint 2).

    Records WHAT was scanned at endpoint granularity so the coverage-aware auto-close can safely
    close endpoint-derived findings once the dedicated endpoint pass exists. ``endpoint_shape_hash``
    is the SHA-256 hex of the versioned canonical identity (see ``endpoint_identity``) — the URL /
    path / query is NEVER stored, so no cleartext token/PII lives here (confidentiality-at-rest; the
    unsalted hash is not un-guessable). Same composite policy FK + status contract as
    ``scan_coverage``. One verdict per (run, phase, pass, asset, endpoint_shape_hash).
    """

    __tablename__ = "scan_endpoint_coverage"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    phase = Column(String(10), nullable=False)
    pass_name = Column(String(64), nullable=False)
    policy_hash = Column(String(64), nullable=False)  # composite FK below → (policy_hash, phase, pass_name)
    endpoint_shape_hash = Column(String(64), nullable=False)  # sha256 hex identity; never a URL/value
    status = Column(_coverage_status_enum(), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "phase",
            "pass_name",
            "asset_id",
            "endpoint_shape_hash",
            name="uq_endpoint_coverage_run_pass_asset_shape",
        ),
        ForeignKeyConstraint(
            ["policy_hash", "phase", "pass_name"],
            ["scan_policy.policy_hash", "scan_policy.phase", "scan_policy.pass_name"],
            name="fk_endpoint_coverage_policy_phase_pass",
        ),
        CheckConstraint(
            "status IN ('covered', 'partial', 'failed', 'skipped', 'unstarted')",
            name="ck_endpoint_coverage_status",
        ),
        CheckConstraint("endpoint_shape_hash ~ '^[0-9a-f]{64}$'", name="ck_endpoint_coverage_shape_hash_hex"),
        Index("idx_endpoint_coverage_tenant_asset_shape", "tenant_id", "asset_id", "endpoint_shape_hash"),
        Index("idx_endpoint_coverage_run", "scan_run_id"),
        Index("idx_endpoint_coverage_policy", "policy_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanEndpointCoverage(run={self.scan_run_id}, pass={self.pass_name!r}, asset={self.asset_id}, "
            f"shape={self.endpoint_shape_hash[:12] if self.endpoint_shape_hash else None}…, "
            f"status={self.status.value if self.status else None})>"
        )
