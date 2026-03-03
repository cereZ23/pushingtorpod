"""Add report_schedules table

Revision ID: 011
Revises: 010
Create Date: 2026-02-26

Adds the report_schedules table for automated PDF/DOCX report
generation and email delivery on daily, weekly, or monthly cadences.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Integer(),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("schedule", sa.String(50), nullable=False),
        sa.Column("recipients", sa.Text(), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("last_sent_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_index(
        "ix_report_schedules_tenant_id",
        "report_schedules",
        ["tenant_id"],
    )
    op.create_index(
        "ix_report_schedules_is_active",
        "report_schedules",
        ["is_active"],
    )


def downgrade() -> None:
    op.drop_index("ix_report_schedules_is_active", table_name="report_schedules")
    op.drop_index("ix_report_schedules_tenant_id", table_name="report_schedules")
    op.drop_table("report_schedules")
