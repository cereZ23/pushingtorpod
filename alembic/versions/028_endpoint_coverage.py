"""endpoint coverage model + finding provenance (Sprint 2, Traccia B)

Persists WHAT was scanned at endpoint granularity so the coverage-aware auto-close can safely close
endpoint-derived findings once the dedicated endpoint pass exists (Sprint 3+).

Identity is a HASH ONLY — ``endpoint_shape_hash`` (64 hex, SHA-256 of a versioned canonical JSON;
see app/services/endpoint_identity.py). The URL / path / query is NEVER stored, so no token / PII /
UUID can leak; scheme + effective port are part of the hash so ``:80``/``:443``/``:8443`` never
collide, and the path is case-preserved.

- ``scan_endpoint_coverage``: one conservative verdict per (run, phase, pass, asset,
  endpoint_shape_hash). Mirrors ``scan_coverage`` (composite policy FK, status CHECK, RLS).
- ``findings`` provenance: ``endpoint_shape_hash`` + ``origin_policy_hash`` (FK → scan_policy, ON
  DELETE SET NULL). ``origin_pass`` is intentionally NOT added — the pass derives from the policy.

Backfill is conservative: historic findings get NULL provenance (= coverage UNKNOWN); nothing is
inferred, so no finding becomes auto-close eligible from this migration. No behaviour change.
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
        sa.Column("endpoint_shape_hash", sa.String(64), nullable=False),  # sha256 hex; never a URL/value
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "scan_run_id",
            "phase",
            "pass_name",
            "asset_id",
            "endpoint_shape_hash",
            name="uq_endpoint_coverage_run_pass_asset_shape",
        ),
        sa.ForeignKeyConstraint(
            ["policy_hash", "phase", "pass_name"],
            ["scan_policy.policy_hash", "scan_policy.phase", "scan_policy.pass_name"],
            name="fk_endpoint_coverage_policy_phase_pass",
        ),
        sa.CheckConstraint(
            "status IN ('covered', 'partial', 'failed', 'skipped', 'unstarted')",
            name="ck_endpoint_coverage_status",
        ),
        sa.CheckConstraint("endpoint_shape_hash ~ '^[0-9a-f]{64}$'", name="ck_endpoint_coverage_shape_hash_hex"),
    )
    op.create_index(
        "idx_endpoint_coverage_tenant_asset_shape",
        "scan_endpoint_coverage",
        ["tenant_id", "asset_id", "endpoint_shape_hash"],
    )
    op.create_index("idx_endpoint_coverage_run", "scan_endpoint_coverage", ["scan_run_id"])
    op.create_index("idx_endpoint_coverage_policy", "scan_endpoint_coverage", ["policy_hash"])

    # Finding provenance (nullable → historic rows = UNKNOWN; nothing inferred). origin_policy_hash
    # is FK-constrained so the DB can never hold a finding pointing at a non-existent policy.
    op.add_column("findings", sa.Column("endpoint_shape_hash", sa.String(64), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "origin_policy_hash",
            sa.String(64),
            sa.ForeignKey("scan_policy.policy_hash", ondelete="SET NULL"),
            nullable=True,
        ),
    )

    if op.get_bind().dialect.name == "postgresql":
        using = f"{_CROSS} OR {_TENANT}"
        op.execute("ALTER TABLE scan_endpoint_coverage ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_endpoint_coverage")
        op.execute(f"CREATE POLICY tenant_isolation ON scan_endpoint_coverage USING ({using}) WITH CHECK ({using})")


def downgrade() -> None:
    op.drop_column("findings", "origin_policy_hash")
    op.drop_column("findings", "endpoint_shape_hash")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_endpoint_coverage")
        op.execute("ALTER TABLE scan_endpoint_coverage DISABLE ROW LEVEL SECURITY")
    op.drop_table("scan_endpoint_coverage")
