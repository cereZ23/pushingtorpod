"""finding lifecycle events — idempotency constraint (UI-2 backend, step 2)

One lifecycle row per (finding, transition, run). The event writer re-checks existence first,
but under a race (or a retried run) this UNIQUE constraint is the backstop that keeps a retried
scan from duplicating events. ``scan_run_id`` is nullable and Postgres treats NULLs as distinct,
which is fine: events are always written WITH the run; NULL only appears later via ON DELETE SET
NULL when a run is purged, and by then the row already exists.
"""

from __future__ import annotations

from alembic import op

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_finding_lifecycle_finding_type_run",
        "finding_lifecycle_events",
        ["finding_id", "event_type", "scan_run_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_finding_lifecycle_finding_type_run",
        "finding_lifecycle_events",
        type_="unique",
    )
