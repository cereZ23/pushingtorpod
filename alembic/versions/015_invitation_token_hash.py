"""Add token_hash column to user_invitations

Stores SHA-256 hash of invitation tokens instead of querying the
existing 'token' column. Existing rows already contain hashes in the
'token' column (applied in application code), so the data migration
copies those values to 'token_hash'. The 'token' column is kept but
is no longer queried.

Revision ID: 015
Revises: 014
Create Date: 2026-03-15
"""

from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add token_hash column (nullable initially to allow data migration)
    op.add_column(
        "user_invitations",
        sa.Column("token_hash", sa.String(64), nullable=True),
    )

    # 2. Backfill: copy existing hashes from 'token' column into 'token_hash'.
    # The application already stores SHA-256 hex digests in 'token', so a
    # straight copy is correct. Any rows where 'token' is NULL or empty get
    # a deterministic hash so the NOT NULL constraint can be applied.
    op.execute(
        """
        UPDATE user_invitations
        SET token_hash = CASE
            WHEN token IS NOT NULL AND length(token) = 64 THEN token
            ELSE encode(sha256(('legacy-' || id::text)::bytea), 'hex')
        END
        WHERE token_hash IS NULL
        """
    )

    # 3. Make token_hash NOT NULL now that all rows have a value
    op.alter_column("user_invitations", "token_hash", nullable=False)

    # 4. Add unique index on token_hash
    op.create_index(
        "idx_invitation_token_hash",
        "user_invitations",
        ["token_hash"],
        unique=True,
    )

    # 5. Make old 'token' column nullable (no longer required)
    op.alter_column("user_invitations", "token", nullable=True)


def downgrade() -> None:
    # Restore token NOT NULL (backfill from token_hash where needed)
    op.execute(
        """
        UPDATE user_invitations
        SET token = token_hash
        WHERE token IS NULL
        """
    )
    op.alter_column("user_invitations", "token", nullable=False)

    op.drop_index("idx_invitation_token_hash", table_name="user_invitations")
    op.drop_column("user_invitations", "token_hash")
