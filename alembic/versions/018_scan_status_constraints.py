"""Add CHECK constraints to status columns

The scan_runs.status and phase_results.status columns are VARCHAR(20) in the
database but the SQLAlchemy model expects Enum values. Add CHECK constraints
to enforce valid values at the database level, preventing invalid strings
from being inserted via raw SQL or server defaults.

Also cleans up any rows with unexpected status values by mapping them to
their closest valid value.

Revision ID: 018
Revises: 017
"""

from alembic import op

revision = "018"
down_revision = "017"


def upgrade():
    # Fix any invalid status values before adding constraints
    op.execute("""
        UPDATE scan_runs
        SET status = 'failed'
        WHERE status NOT IN ('pending', 'running', 'completed', 'failed', 'cancelled')
    """)
    op.execute("""
        UPDATE phase_results
        SET status = 'failed'
        WHERE status NOT IN ('pending', 'running', 'completed', 'failed', 'skipped')
    """)

    # Add CHECK constraints
    op.execute("""
        ALTER TABLE scan_runs
        ADD CONSTRAINT ck_scan_runs_status
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
    """)
    op.execute("""
        ALTER TABLE phase_results
        ADD CONSTRAINT ck_phase_results_status
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped'))
    """)


def downgrade():
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS ck_scan_runs_status")
    op.execute("ALTER TABLE phase_results DROP CONSTRAINT IF EXISTS ck_phase_results_status")
