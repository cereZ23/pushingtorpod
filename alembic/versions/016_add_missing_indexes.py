"""Add missing database indexes for common query patterns

Performance analysis identified four missing indexes that cause sequential
scans on high-traffic query paths:

1. findings(asset_id, status) -- most common query: list findings for an
   asset filtered by status.  Existing composite indexes include severity
   or first_seen columns, making them suboptimal when the query only
   filters on asset_id + status.

2. findings(first_seen) -- dashboard sorting, exposure timeline, and
   "new findings in the last N days" queries all ORDER BY / filter on
   first_seen without a leading-column index.

3. observations(asset_id) -- foreign key to assets table is completely
   unindexed, causing sequential scans on JOINs and CASCADE DELETEs.

4. Partial index assets(tenant_id, risk_score) WHERE is_active = true --
   the dashboard risk-distribution widget queries active assets by tenant
   ordered by risk_score.  The existing idx_assets_active_only includes
   type and last_seen columns, which adds overhead for this specific
   pattern.

Revision ID: 016
Revises: 015
Create Date: 2026-03-15
"""

from alembic import op

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. findings(asset_id, status)
    # Covers the most frequent query: SELECT ... FROM findings
    #   WHERE asset_id = :id AND status = 'OPEN'
    op.create_index(
        "idx_findings_asset_status",
        "findings",
        ["asset_id", "status"],
        unique=False,
    )

    # 2. findings(first_seen)
    # Covers dashboard ORDER BY first_seen DESC and
    # WHERE first_seen >= :cutoff range scans
    op.create_index(
        "idx_findings_first_seen",
        "findings",
        ["first_seen"],
        unique=False,
    )

    # 3. observations(asset_id)
    # Unindexed FK -- required for efficient JOINs and CASCADE DELETEs
    op.create_index(
        "idx_observations_asset_id",
        "observations",
        ["asset_id"],
        unique=False,
    )

    # 4. Partial index: assets(tenant_id, risk_score) WHERE is_active
    # Optimises: SELECT ... FROM assets
    #   WHERE tenant_id = :tid AND is_active = true
    #   ORDER BY risk_score DESC
    # Leaner than idx_assets_active_only which carries type + last_seen.
    op.execute(
        """
        CREATE INDEX idx_assets_tenant_risk_active_partial
        ON assets (tenant_id, risk_score DESC)
        WHERE is_active = true
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_assets_tenant_risk_active_partial")
    op.drop_index("idx_observations_asset_id", table_name="observations")
    op.drop_index("idx_findings_first_seen", table_name="findings")
    op.drop_index("idx_findings_asset_status", table_name="findings")
