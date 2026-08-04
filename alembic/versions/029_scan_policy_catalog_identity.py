"""scan_policy identity refinements: catalog_digest + classifier_version (Sprint 3, step 2)

The http_endpoint pass's applicable set is a CLASSIFIED subset of the stock catalog, so it is NOT
fully determined by roots+severity+tags+revision — it also depends on the classifier. The derived
``catalog_digest`` and the ``classifier_version`` therefore participate in ``policy_hash`` (see
app/services/scan_policy.py). This migration persists them on ``scan_policy`` so the stored row
mirrors the FULL manifest that produced the hash (not just part of it).

Both columns are NULLABLE and NULL for every existing pass — their identity is unchanged and their
policy_hash is byte-for-byte what it was, so no policy row is invalidated or recreated.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_policy", sa.Column("catalog_digest", sa.String(64), nullable=True))
    op.add_column("scan_policy", sa.Column("classifier_version", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_policy", "classifier_version")
    op.drop_column("scan_policy", "catalog_digest")
