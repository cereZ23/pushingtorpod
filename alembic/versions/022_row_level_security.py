"""Row-Level Security policies on tenant data tables

Revision ID: 022
Revises: 021
Create Date: 2026-07-22

Enables Postgres RLS on the tenant *data* tables so the database itself refuses
to return another tenant's rows. Policies read two transaction-local GUCs set by
the app (app.database._apply_tenant_guc):
  - app.current_tenant_id : the active tenant
  - app.cross_tenant      : 'on' for legitimately cross-tenant work

Safe to apply while the app still connects as the DB owner (owner bypasses RLS);
it becomes load-bearing only after the cutover to the non-owner role.

Auth tables (tenant_memberships/api_keys/user_invitations) and audit tables are
intentionally excluded for now — they have cross-tenant access flows.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None

_TENANT = "tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::int"
_CROSS = "current_setting('app.cross_tenant', true) = 'on'"

# Direct tenant_id data tables (NOT NULL tenant_id).
_DIRECT = [
    "assets",
    "seeds",
    "projects",
    "scan_runs",
    "observations",
    "risk_scores",
    "alerts",
    "alert_policies",
    "relationships",
    "issues",
    "ticketing_configs",
    "tickets",
    "report_schedules",
    "scan_authorizations",
]

# tenant_id nullable, NULL = global (visible to all).
_DIRECT_NULLABLE = ["suppressions"]

# Transitively scoped: child -> (fk column, parent table).
_TRANSITIVE = {
    "services": ("asset_id", "assets"),
    "findings": ("asset_id", "assets"),
    "events": ("asset_id", "assets"),
    "certificates": ("asset_id", "assets"),
    "endpoints": ("asset_id", "assets"),
    "scopes": ("project_id", "projects"),
    "scan_profiles": ("project_id", "projects"),
    "phase_results": ("scan_run_id", "scan_runs"),
    "issue_findings": ("issue_id", "issues"),
    "issue_activities": ("issue_id", "issues"),
}


def _table_exists(table: str) -> bool:
    # Some tables are created by the models (create_all), not by migrations, so
    # a pure-migration DB (CI) may not have them yet. Prod has them all.
    return op.get_bind().execute(sa.text("SELECT to_regclass(:t)"), {"t": f"public.{table}"}).scalar() is not None


def _enable(table: str, using: str) -> None:
    if not _table_exists(table):
        return
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({using}) WITH CHECK ({using})")


def upgrade() -> None:
    for t in _DIRECT:
        _enable(t, f"{_CROSS} OR {_TENANT}")
    for t in _DIRECT_NULLABLE:
        _enable(t, f"{_CROSS} OR tenant_id IS NULL OR {_TENANT}")
    for child, (fk, parent) in _TRANSITIVE.items():
        subq = f"{fk} IN (SELECT id FROM {parent} WHERE {_TENANT})"
        _enable(child, f"{_CROSS} OR {subq}")


def downgrade() -> None:
    tables = list(_DIRECT) + list(_DIRECT_NULLABLE) + list(_TRANSITIVE.keys())
    for t in tables:
        if not _table_exists(t):
            continue
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
