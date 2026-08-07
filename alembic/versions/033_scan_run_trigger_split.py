"""scan_runs: split triggered_by into trigger_type (server-set) + trigger_label (descriptive)

triggered_by was overloaded (provenance AND ad-hoc diagnostic labels), so the UI could not render an
honest provenance badge. Add:
  - trigger_type  (manual/scheduled/api/retest, nullable, CHECK) — the provenance, the ONLY field the
    UI/authorization reads;
  - trigger_label (nullable) — an optional descriptive string, display-only.

Backfill from the legacy value: recognised provenance → trigger_type (scheduler→scheduled); anything
else (a custom label like "t2-cutover-verify") → trigger_type NULL (never guessed) + trigger_label =
the custom value. triggered_by is kept for back-compat, written henceforth only by
services.scan_triggers.apply_trigger.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None

_KNOWN = ("manual", "scheduler", "schedule", "api", "retest")


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("trigger_type", sa.String(16), nullable=True))
    op.add_column("scan_runs", sa.Column("trigger_label", sa.String(100), nullable=True))
    op.create_check_constraint(
        "ck_scan_run_trigger_type",
        "scan_runs",
        "trigger_type IS NULL OR trigger_type IN ('manual', 'scheduled', 'api', 'retest')",
    )
    # Backfill provenance from the recognised legacy values; scheduler/schedule → scheduled.
    op.execute(
        """
        UPDATE scan_runs SET trigger_type = CASE
            WHEN triggered_by = 'manual'    THEN 'manual'
            WHEN triggered_by IN ('scheduler', 'schedule') THEN 'scheduled'
            WHEN triggered_by = 'api'       THEN 'api'
            WHEN triggered_by = 'retest'    THEN 'retest'
            ELSE NULL
        END
        WHERE trigger_type IS NULL
        """
    )
    # Any legacy value that was NOT a recognised provenance is a custom label → preserve it.
    op.execute(
        """
        UPDATE scan_runs SET trigger_label = triggered_by
        WHERE triggered_by IS NOT NULL
          AND triggered_by NOT IN ('manual', 'scheduler', 'schedule', 'api', 'retest')
          AND trigger_label IS NULL
        """
    )


def downgrade() -> None:
    op.drop_constraint("ck_scan_run_trigger_type", "scan_runs", type_="check")
    op.drop_column("scan_runs", "trigger_label")
    op.drop_column("scan_runs", "trigger_type")
