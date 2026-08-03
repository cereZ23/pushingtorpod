"""scan_policy_catalog: per-policy catalog build fingerprint (count + digest)

Revision ID: 025
Revises: 024
Create Date: 2026-08-03

Additive: one GLOBAL 1:1 companion to ``scan_policy`` recording that a policy's
applicable-detector catalog has been FULLY built, plus its exact fingerprint
(detector_count + a digest over the sorted rows). The emit uses this to safely skip
re-parsing thousands of templates on an unchanged policy WITHOUT falling back to the
unsafe "any row exists" shortcut — which would treat a partial or tampered catalog
(e.g. an extra, non-applicable detector) as complete and could later authorise a wrong
auto-close. Policy-derived and tenant-independent, so no tenant_id and no RLS.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_policy_catalog",
        sa.Column(
            "policy_hash",
            sa.String(64),
            sa.ForeignKey("scan_policy.policy_hash", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("detector_count", sa.Integer(), nullable=False),
        sa.Column("catalog_digest", sa.String(64), nullable=False),
        sa.Column("built_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("scan_policy_catalog")
