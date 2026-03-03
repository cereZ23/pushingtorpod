"""RBAC analyst role, invitations, MFA, and password reset

Revision ID: 012
Revises: 011
Create Date: 2026-02-27

Renames 'member' role to 'analyst', adds user_invitations table,
and extends users with MFA and password reset fields.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Rename 'member' role to 'analyst' in tenant_memberships
    op.execute(
        "UPDATE tenant_memberships SET role = 'analyst' WHERE role = 'member'"
    )

    # 2. Add MFA and password-reset columns to users
    op.add_column("users", sa.Column("mfa_secret", sa.String(255), nullable=True))
    op.add_column(
        "users", sa.Column("mfa_enabled", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column(
        "users", sa.Column("password_reset_token", sa.String(255), nullable=True)
    )
    op.add_column(
        "users", sa.Column("password_reset_expires", sa.DateTime(), nullable=True)
    )
    op.create_index(
        "idx_users_password_reset_token", "users", ["password_reset_token"], unique=False
    )

    # 3. Create user_invitations table
    op.create_table(
        "user_invitations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("token", sa.String(255), nullable=False, unique=True),
        sa.Column("invited_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("idx_invitation_token", "user_invitations", ["token"], unique=True)
    op.create_index(
        "idx_invitation_tenant_email",
        "user_invitations",
        ["tenant_id", "email"],
    )


def downgrade() -> None:
    op.drop_table("user_invitations")
    op.drop_index("idx_users_password_reset_token", table_name="users")
    op.drop_column("users", "password_reset_expires")
    op.drop_column("users", "password_reset_token")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
    op.execute(
        "UPDATE tenant_memberships SET role = 'member' WHERE role = 'analyst'"
    )
