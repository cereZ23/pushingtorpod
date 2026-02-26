"""Add SSO fields to users table

Revision ID: 010
Revises: 009
Create Date: 2026-02-26

Adds sso_provider and sso_subject_id columns to the users table
for SAML/OIDC single sign-on support. Also makes hashed_password
nullable for SSO-only users who have no local password.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("sso_provider", sa.String(50), nullable=True))
    op.add_column("users", sa.Column("sso_subject_id", sa.String(255), nullable=True))
    op.create_index("ix_users_sso_provider", "users", ["sso_provider"])
    op.create_index("ix_users_sso_subject_id", "users", ["sso_subject_id"])

    # Make hashed_password nullable for SSO-only users
    op.alter_column("users", "hashed_password", existing_type=sa.String(255), nullable=True)


def downgrade() -> None:
    # Restore NOT NULL on hashed_password (set empty hash for SSO users first)
    op.execute("UPDATE users SET hashed_password = '' WHERE hashed_password IS NULL")
    op.alter_column("users", "hashed_password", existing_type=sa.String(255), nullable=False)

    op.drop_index("ix_users_sso_subject_id", table_name="users")
    op.drop_index("ix_users_sso_provider", table_name="users")
    op.drop_column("users", "sso_subject_id")
    op.drop_column("users", "sso_provider")
