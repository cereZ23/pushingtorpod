"""Add matched_at, host columns to findings

These columns were defined in the ORM model (Sprint 3: Nuclei integration)
but never had a corresponding migration. They may already exist in production
databases that had them added manually or via metadata.create_all().

Revision ID: 019
Revises: 018
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    """Check if a column already exists in the table."""
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = [c["name"] for c in inspector.get_columns(table)]
    return column in columns


def upgrade() -> None:
    if not _column_exists("findings", "matched_at"):
        op.add_column("findings", sa.Column("matched_at", sa.String(2048), nullable=True))
    if not _column_exists("findings", "host"):
        op.add_column("findings", sa.Column("host", sa.String(500), nullable=True))


def downgrade() -> None:
    if _column_exists("findings", "host"):
        op.drop_column("findings", "host")
    if _column_exists("findings", "matched_at"):
        op.drop_column("findings", "matched_at")
