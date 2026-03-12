"""Add audit_logs table.

Revision ID: 014
Revises: 013
Create Date: 2026-03-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = '014'
down_revision = '013'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        sa.Column('event_type', sa.String(100), nullable=False, index=True),
        sa.Column('user_id', sa.Integer(), index=True),
        sa.Column('tenant_id', sa.Integer(), index=True),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('resource', sa.String(255)),
        sa.Column('resource_id', sa.String(255)),
        sa.Column('result', sa.String(50), nullable=False),
        sa.Column('details', JSONB()),
        sa.Column('error_message', sa.Text()),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('request_id', sa.String(100)),
        sa.Column('endpoint', sa.String(255)),
        sa.Column('method', sa.String(10)),
    )
    op.create_index('idx_audit_user_timestamp', 'audit_logs', ['user_id', 'timestamp'])
    op.create_index('idx_audit_tenant_timestamp', 'audit_logs', ['tenant_id', 'timestamp'])


def downgrade() -> None:
    op.drop_index('idx_audit_tenant_timestamp', table_name='audit_logs')
    op.drop_index('idx_audit_user_timestamp', table_name='audit_logs')
    op.drop_table('audit_logs')
