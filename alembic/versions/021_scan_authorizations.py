"""scan_authorizations table (scope authorization of record)

Revision ID: 021
Revises: 020
Create Date: 2026-07-21

Additive: creates one new table. No changes to existing tables, so it is safe
to apply on a live database.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_authorizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope_entries", sa.JSON(), nullable=False),
        sa.Column("authorized_by", sa.String(255), nullable=True),
        sa.Column("authorization_ref", sa.String(500), nullable=True),
        sa.Column("authorized_at", sa.DateTime(), nullable=True),
        sa.Column("valid_from", sa.DateTime(), nullable=True),
        sa.Column("valid_until", sa.DateTime(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_scan_auth_tenant_active", "scan_authorizations", ["tenant_id", "is_active"])


def downgrade() -> None:
    op.drop_index("idx_scan_auth_tenant_active", table_name="scan_authorizations")
    op.drop_table("scan_authorizations")
