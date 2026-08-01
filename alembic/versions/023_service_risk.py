"""Persisted per-service risk (risk_score / risk_level / risk_components)

Revision ID: 023
Revises: 022
Create Date: 2026-08-01

Services now carry an explainable risk (the same model as assets/findings),
computed and persisted by phase 11. Persisting it lets the API sort/filter
services globally by risk before paginating, and expose the factor breakdown
without recomputing per request. All columns are nullable — existing rows read
as NULL ("—" in the UI) until the next scan's phase 11 backfills them.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("services", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column("services", sa.Column("risk_level", sa.String(length=20), nullable=True))
    op.add_column("services", sa.Column("risk_components", sa.JSON(), nullable=True))
    op.create_index("idx_service_risk_score", "services", ["risk_score"])


def downgrade() -> None:
    op.drop_index("idx_service_risk_score", table_name="services")
    op.drop_column("services", "risk_components")
    op.drop_column("services", "risk_level")
    op.drop_column("services", "risk_score")
