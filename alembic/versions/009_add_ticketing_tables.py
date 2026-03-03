"""Add ticketing integration tables

Revision ID: 009
Revises: 008
Create Date: 2026-02-25

Creates the ticketing_configs and tickets tables for bi-directional
Jira and ServiceNow integration.

Tables:
    ticketing_configs - Per-tenant ticketing provider configuration (encrypted creds)
    tickets           - Individual ticket records linking findings to external tickets
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the old tickets table (from risk.py placeholder) if it exists
    # The old schema had issue_id; the new one uses finding_id
    from sqlalchemy import inspect
    conn = op.get_bind()
    inspector = inspect(conn)
    if "tickets" in inspector.get_table_names():
        op.drop_table("tickets")

    # --- ticketing_configs ---
    op.create_table(
        "ticketing_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("auto_create_on_triage", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sync_status_back", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), onupdate=sa.func.now()),
    )
    op.create_index("idx_ticketing_config_tenant", "ticketing_configs", ["tenant_id"])
    op.create_index("idx_ticketing_config_active", "ticketing_configs", ["tenant_id", "is_active"])

    # --- tickets ---
    op.create_table(
        "tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("external_url", sa.String(2048)),
        sa.Column("external_status", sa.String(100)),
        sa.Column("sync_status", sa.String(50), server_default="synced"),
        sa.Column("sync_error", sa.Text()),
        sa.Column("last_synced_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), onupdate=sa.func.now()),
        sa.Column("external_metadata", sa.JSON()),
    )
    op.create_index("idx_ticket_tenant", "tickets", ["tenant_id"])
    op.create_index("idx_ticket_finding", "tickets", ["finding_id"])
    op.create_index("idx_ticket_external_id", "tickets", ["external_id"])
    op.create_index("idx_ticket_sync_status", "tickets", ["sync_status"])
    op.create_index("idx_ticket_tenant_provider", "tickets", ["tenant_id", "provider"])


def downgrade() -> None:
    op.drop_index("idx_ticket_tenant_provider", table_name="tickets")
    op.drop_index("idx_ticket_sync_status", table_name="tickets")
    op.drop_index("idx_ticket_external_id", table_name="tickets")
    op.drop_index("idx_ticket_finding", table_name="tickets")
    op.drop_index("idx_ticket_tenant", table_name="tickets")
    op.drop_table("tickets")

    op.drop_index("idx_ticketing_config_active", table_name="ticketing_configs")
    op.drop_index("idx_ticketing_config_tenant", table_name="ticketing_configs")
    op.drop_table("ticketing_configs")
