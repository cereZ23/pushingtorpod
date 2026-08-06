"""scan_runs.scan_tier — persist the tier each run executed (UI traceability)

The tier lived only on the linked ScanProfile, so the scan list/detail could not tell T1/T2/T3
apart (and a later profile edit would retro-change the apparent tier). Snapshot it on the run.

Nullable on purpose: of the existing runs the vast majority have NO linked profile (manual/legacy
and untiered retests), so there is no reliable tier to assign — those stay NULL and the UI shows
"Unknown" rather than guessing from duration/phases. Backfill only the runs that DO have a profile.
A CHECK keeps the value in {1,2,3} (or NULL).
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "032"
down_revision = "031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("scan_tier", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_scan_run_tier",
        "scan_runs",
        "scan_tier IS NULL OR scan_tier IN (1, 2, 3)",
    )
    # Backfill ONLY runs with a resolvable profile tier; profile-less/legacy runs stay NULL (Unknown).
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "UPDATE scan_runs sr SET scan_tier = sp.scan_tier "
            "FROM scan_profiles sp WHERE sp.id = sr.profile_id AND sr.scan_tier IS NULL"
        )
    else:
        op.execute(
            "UPDATE scan_runs SET scan_tier = ("
            "SELECT sp.scan_tier FROM scan_profiles sp WHERE sp.id = scan_runs.profile_id"
            ") WHERE profile_id IS NOT NULL AND scan_tier IS NULL"
        )


def downgrade() -> None:
    op.drop_constraint("ck_scan_run_tier", "scan_runs", type_="check")
    op.drop_column("scan_runs", "scan_tier")
