"""finding lifecycle events — durable, queryable auto-close explainability (UI-2 backend, step 1)

Persists the coverage-aware auto-close lifecycle as QUERYABLE events (detected / eligible_miss /
miss_reset / would_close / auto_closed / reopened) so the UI can prove WHY a finding was opened,
held ineligible, or closed — today that reasoning lives only in an application log line. Step 2
writes the ``auto_closed`` event in the SAME transaction as the OPEN→FIXED close.

Confidentiality-at-rest, same as the coverage tables: NO cleartext URL and NO full coverage/policy
hash is stored. ``detail`` is a small JSON with only non-sensitive context (streak, threshold,
coverage scope, origin policy tier, an ABBREVIATED shape prefix). Tenant-scoped + RLS.

This migration only creates the table (no backfill — step 3 does a minimal current-state backfill,
never invented history). No behaviour change on its own.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None

_TENANT = "tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::int"
_CROSS = "current_setting('app.cross_tenant', true) = 'on'"

_EVENT_TYPES = ("detected", "eligible_miss", "miss_reset", "would_close", "auto_closed", "reopened")


def upgrade() -> None:
    op.create_table(
        "finding_lifecycle_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        # the run that produced the event; SET NULL so purging a run keeps the audit trail.
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),  # small, URL-free context only (no full hash)
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "event_type IN ('detected', 'eligible_miss', 'miss_reset', 'would_close', 'auto_closed', 'reopened')",
            name="ck_finding_lifecycle_event_type",
        ),
    )
    # Timeline query for one finding, newest last; plus tenant scan for the dashboard/isolation.
    op.create_index("idx_finding_lifecycle_finding_created", "finding_lifecycle_events", ["finding_id", "created_at"])
    op.create_index("idx_finding_lifecycle_tenant", "finding_lifecycle_events", ["tenant_id"])
    op.create_index("idx_finding_lifecycle_run", "finding_lifecycle_events", ["scan_run_id"])

    if op.get_bind().dialect.name == "postgresql":
        using = f"{_CROSS} OR {_TENANT}"
        op.execute("ALTER TABLE finding_lifecycle_events ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_lifecycle_events")
        op.execute(f"CREATE POLICY tenant_isolation ON finding_lifecycle_events USING ({using}) WITH CHECK ({using})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_lifecycle_events")
        op.execute("ALTER TABLE finding_lifecycle_events DISABLE ROW LEVEL SECURITY")
    op.drop_table("finding_lifecycle_events")
