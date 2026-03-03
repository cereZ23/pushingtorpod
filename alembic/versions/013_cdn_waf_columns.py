"""Add CDN/WAF/Cloud provider columns to assets table.

These columns are populated by Phase 5b (cdncheck) of the scan pipeline.
Used by the risk scoring engine to apply CDN discount factor.

Revision ID: 013
Revises: 012
Create Date: 2026-02-28
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = inspect(bind)
    columns = [c["name"] for c in insp.get_columns(table)]
    return column in columns


def upgrade() -> None:
    if not _column_exists("assets", "cdn_name"):
        op.add_column("assets", sa.Column("cdn_name", sa.String(100), nullable=True))
    if not _column_exists("assets", "waf_name"):
        op.add_column("assets", sa.Column("waf_name", sa.String(100), nullable=True))
    if not _column_exists("assets", "cloud_provider"):
        op.add_column("assets", sa.Column("cloud_provider", sa.String(100), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "cloud_provider")
    op.drop_column("assets", "waf_name")
    op.drop_column("assets", "cdn_name")
