"""phase_results: allow 'partial' status

Revision ID: 027
Revises: 026
Create Date: 2026-08-03

``PhaseStatus.PARTIAL = "partial"`` was added when partial-success became first-class,
but the ``ck_phase_results_status`` CHECK constraint (migration 018) was never updated —
so writing a PARTIAL phase result raises a CheckViolation and the whole pipeline task
retries/fails. This surfaced when nuclei phase 9 started TRUNCATING (coverage_complete=
False → PARTIAL) instead of hard-failing. Add 'partial' to the allowed set.
"""

from __future__ import annotations

from alembic import op

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None

_WITH_PARTIAL = "('pending', 'running', 'completed', 'partial', 'failed', 'skipped')"
_WITHOUT_PARTIAL = "('pending', 'running', 'completed', 'failed', 'skipped')"


def upgrade() -> None:
    op.execute("ALTER TABLE phase_results DROP CONSTRAINT IF EXISTS ck_phase_results_status")
    op.execute(f"ALTER TABLE phase_results ADD CONSTRAINT ck_phase_results_status CHECK (status IN {_WITH_PARTIAL})")


def downgrade() -> None:
    op.execute("ALTER TABLE phase_results DROP CONSTRAINT IF EXISTS ck_phase_results_status")
    # A rollback can't re-add the stricter CHECK while 'partial' rows exist (they'd violate
    # it and abort the downgrade). Collapse them to 'failed' first — a partial phase did not
    # complete — so the constraint applies cleanly.
    op.execute("UPDATE phase_results SET status = 'failed' WHERE status = 'partial'")
    op.execute(f"ALTER TABLE phase_results ADD CONSTRAINT ck_phase_results_status CHECK (status IN {_WITHOUT_PARTIAL})")
