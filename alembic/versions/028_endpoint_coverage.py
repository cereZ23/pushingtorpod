"""endpoint coverage model + finding provenance (Sprint 2, Traccia B)

Persists WHAT was actually scanned at endpoint granularity so the coverage-aware auto-close can
safely close endpoint-derived findings once the dedicated endpoint pass exists (Sprint 3+).

- ``scan_endpoint_coverage``: one conservative verdict per (run, phase, pass, asset, endpoint_shape).
  ``endpoint_shape`` is the canonical shape STRING (host | id-collapsed path | sorted param NAMES —
  NO query/token values). Mirrors ``scan_coverage`` (composite policy FK, status CHECK, RLS).
- ``findings`` provenance: ``origin_pass`` / ``endpoint_shape`` / ``origin_policy_hash`` — where/how
  the finding was produced, so the consumer knows which coverage row authorises it.

Backfill is conservative: historic findings get NULL provenance (= coverage UNKNOWN); nothing is
inferred, and no finding becomes auto-close eligible from this migration. No behaviour change.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None

_TENANT = "tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::int"
_CROSS = "current_setting('app.cross_tenant', true) = 'on'"


def upgrade() -> None:
    op.create_table(
        "scan_endpoint_coverage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("phase", sa.String(10), nullable=False),
        sa.Column("pass_name", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("endpoint_shape", sa.String(1024), nullable=False),  # host|/id-path|param,names — no values
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "scan_run_id", "phase", "pass_name", "asset_id", "endpoint_shape",
            name="uq_endpoint_coverage_run_pass_asset_shape",
        ),
        # the coverage's (policy_hash, phase, pass_name) MUST match the policy's own — no coverage
        # can name a policy for a different phase/pass (same contract as scan_coverage).
        sa.ForeignKeyConstraint(
            ["policy_hash", "phase", "pass_name"],
            ["scan_policy.policy_hash", "scan_policy.phase", "scan_policy.pass_name"],
            name="fk_endpoint_coverage_policy_phase_pass",
        ),
        sa.CheckConstraint(
            "status IN ('covered', 'partial', 'failed', 'skipped', 'unstarted')",
            name="ck_endpoint_coverage_status",
        ),
    )
    op.create_index(
        "idx_endpoint_coverage_tenant_asset_shape",
        "scan_endpoint_coverage",
        ["tenant_id", "asset_id", "endpoint_shape"],
    )
    op.create_index("idx_endpoint_coverage_run", "scan_endpoint_coverage", ["scan_run_id"])
    op.create_index("idx_endpoint_coverage_policy", "scan_endpoint_coverage", ["policy_hash"])

    # Finding provenance (nullable → historic rows = UNKNOWN; nothing inferred).
    op.add_column("findings", sa.Column("origin_pass", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("endpoint_shape", sa.String(1024), nullable=True))
    op.add_column("findings", sa.Column("origin_policy_hash", sa.String(64), nullable=True))

    # RLS only on the tenant-scoped table (Postgres only; mirrors migrations 022/024).
    if op.get_bind().dialect.name == "postgresql":
        using = f"{_CROSS} OR {_TENANT}"
        op.execute("ALTER TABLE scan_endpoint_coverage ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_endpoint_coverage")
        op.execute(f"CREATE POLICY tenant_isolation ON scan_endpoint_coverage USING ({using}) WITH CHECK ({using})")


def downgrade() -> None:
    op.drop_column("findings", "origin_policy_hash")
    op.drop_column("findings", "endpoint_shape")
    op.drop_column("findings", "origin_pass")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_endpoint_coverage")
        op.execute("ALTER TABLE scan_endpoint_coverage DISABLE ROW LEVEL SECURITY")
    op.drop_table("scan_endpoint_coverage")
