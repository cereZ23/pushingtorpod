"""Add matched_at, host columns to findings

These columns were defined in the ORM model (Sprint 3: Nuclei integration)
but never had a corresponding migration.

Revision ID: 019
Revises: 018
"""
from alembic import op
import sqlalchemy as sa

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("matched_at", sa.String(2048), nullable=True))
    op.add_column("findings", sa.Column("host", sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "host")
    op.drop_column("findings", "matched_at")
