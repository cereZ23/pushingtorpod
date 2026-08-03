"""findings: coverage-aware auto-close bookkeeping (miss streak + run attribution)

Revision ID: 026
Revises: 025
Create Date: 2026-08-03

Additive columns on ``findings`` for the P-C dry-run of the coverage-aware auto-close:
- ``eligible_miss_streak`` — consecutive runs a finding was eligible to close yet not
  detected (CHECK >= 0);
- ``last_eligible_run_id`` — the run that last incremented the streak, so a retried run
  can't double-count;
- ``last_detected_scan_run_id`` — attributes the most recent detection to a specific run.

Both run refs are ``ON DELETE SET NULL`` (a purged run must not cascade-delete findings).
No behaviour change: nothing closes off these columns yet.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("eligible_miss_streak", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "findings",
        sa.Column("last_eligible_run_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("last_detected_scan_run_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_finding_last_eligible_run",
        "findings",
        "scan_runs",
        ["last_eligible_run_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_finding_last_detected_run",
        "findings",
        "scan_runs",
        ["last_detected_scan_run_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint("ck_finding_miss_streak_nonneg", "findings", "eligible_miss_streak >= 0")
    op.create_index("idx_finding_last_eligible_run", "findings", ["last_eligible_run_id"])
    op.create_index("idx_finding_last_detected_run", "findings", ["last_detected_scan_run_id"])


def downgrade() -> None:
    op.drop_index("idx_finding_last_detected_run", table_name="findings")
    op.drop_index("idx_finding_last_eligible_run", table_name="findings")
    op.drop_constraint("ck_finding_miss_streak_nonneg", "findings", type_="check")
    op.drop_constraint("fk_finding_last_detected_run", "findings", type_="foreignkey")
    op.drop_constraint("fk_finding_last_eligible_run", "findings", type_="foreignkey")
    op.drop_column("findings", "last_detected_scan_run_id")
    op.drop_column("findings", "last_eligible_run_id")
    op.drop_column("findings", "eligible_miss_streak")
