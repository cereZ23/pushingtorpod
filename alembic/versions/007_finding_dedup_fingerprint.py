"""Add fingerprint and occurrence_count columns to findings for deduplication.

Revision ID: 007
Revises: 006
Create Date: 2026-02-25

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('fingerprint', sa.String(64), nullable=True))
    op.add_column('findings', sa.Column('occurrence_count', sa.Integer(), server_default='1', nullable=False))
    op.create_index('idx_finding_fingerprint', 'findings', ['fingerprint'], unique=True)


def downgrade() -> None:
    op.drop_index('idx_finding_fingerprint', table_name='findings')
    op.drop_column('findings', 'occurrence_count')
    op.drop_column('findings', 'fingerprint')
