"""coverage ledger: scan_policy, scan_policy_templates, scan_coverage

Revision ID: 024
Revises: 023
Create Date: 2026-08-02

Additive: creates three new tables. ``scan_policy`` and ``scan_policy_templates`` are
GLOBAL (policy_hash is content-derived, tenant-independent → identical policies dedupe),
so they carry no tenant_id and no RLS. ``scan_coverage`` is tenant-scoped and gets a
Row-Level-Security policy mirroring migration 022 (reads the app.current_tenant_id /
app.cross_tenant GUCs). No changes to existing tables — safe to apply on a live DB.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None

_TENANT = "tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::int"
_CROSS = "current_setting('app.cross_tenant', true) = 'on'"


def upgrade() -> None:
    # --- global: immutable policy identity -----------------------------------
    op.create_table(
        "scan_policy",
        sa.Column("policy_hash", sa.String(64), primary_key=True),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("engine_name", sa.String(32), nullable=False),
        sa.Column("engine_version", sa.String(128), nullable=False),
        sa.Column("rule_revision", sa.String(64), nullable=False),
        sa.Column("phase", sa.String(10), nullable=False),
        sa.Column("pass_name", sa.String(64), nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("severity", sa.JSON(), nullable=False),
        sa.Column("rule_roots", sa.JSON(), nullable=False),
        sa.Column("exclude_tags", sa.JSON(), nullable=False),
        sa.Column("relevant_flags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        # anchors the coverage composite FK (policy_hash is already the PK)
        sa.UniqueConstraint("policy_hash", "phase", "pass_name", name="uq_policy_phase_pass"),
    )
    op.create_index("idx_scan_policy_pass", "scan_policy", ["engine_name", "pass_name"])

    # --- global: applicable detector catalog per policy ----------------------
    op.create_table(
        "scan_policy_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "policy_hash",
            sa.String(64),
            sa.ForeignKey("scan_policy.policy_hash", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("detector_id", sa.String(255), nullable=False),
        sa.Column("relative_path", sa.String(1024), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.UniqueConstraint("policy_hash", "detector_id", name="uq_policy_template"),
    )
    op.create_index("idx_policy_template_policy", "scan_policy_templates", ["policy_hash"])
    op.create_index("idx_policy_template_detector", "scan_policy_templates", ["detector_id"])

    # --- tenant-scoped: per (run, pass, asset) coverage ----------------------
    op.create_table(
        "scan_coverage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("phase", sa.String(10), nullable=False),
        sa.Column("pass_name", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("scan_run_id", "phase", "pass_name", "asset_id", name="uq_coverage_run_pass_asset"),
        # coverage's (policy_hash, phase, pass_name) must match the policy's own
        sa.ForeignKeyConstraint(
            ["policy_hash", "phase", "pass_name"],
            ["scan_policy.policy_hash", "scan_policy.phase", "scan_policy.pass_name"],
            name="fk_coverage_policy_phase_pass",
        ),
        sa.CheckConstraint(
            "status IN ('covered', 'partial', 'failed', 'skipped', 'unstarted')", name="ck_coverage_status"
        ),
    )
    op.create_index(
        "idx_coverage_tenant_asset_pass", "scan_coverage", ["tenant_id", "asset_id", "pass_name", "created_at"]
    )
    op.create_index("idx_coverage_run", "scan_coverage", ["scan_run_id"])
    op.create_index("idx_coverage_policy", "scan_coverage", ["policy_hash"])

    # RLS only on the tenant-scoped table (Postgres only; mirrors migration 022).
    if op.get_bind().dialect.name == "postgresql":
        using = f"{_CROSS} OR {_TENANT}"
        op.execute("ALTER TABLE scan_coverage ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_coverage")
        op.execute(f"CREATE POLICY tenant_isolation ON scan_coverage USING ({using}) WITH CHECK ({using})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_coverage")
        op.execute("ALTER TABLE scan_coverage DISABLE ROW LEVEL SECURITY")
    op.drop_table("scan_coverage")
    op.drop_table("scan_policy_templates")
    op.drop_table("scan_policy")
