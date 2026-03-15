"""Add ondelete CASCADE/SET NULL to core foreign keys

Several foreign keys in the schema were created without ondelete actions,
causing constraint violations when deleting parent rows (assets, tenants,
findings, scan_runs) or leaving orphaned child records.

This migration drops and recreates the affected FK constraints with the
appropriate ondelete behaviour:

- CASCADE for non-nullable child FKs (child must not exist without parent)
- SET NULL for nullable FKs (preserve child row, clear the reference)

Targeted tables and their parent references:

  CASCADE (non-nullable, child cannot exist without parent):
    services.asset_id         -> assets.id
    findings.asset_id         -> assets.id
    events.asset_id           -> assets.id
    assets.tenant_id          -> tenants.id
    seeds.tenant_id           -> tenants.id
    tickets.finding_id        -> findings.id
    phase_results.scan_run_id -> scan_runs.id

  SET NULL (nullable, keep child row but clear the dangling reference):
    observations.asset_id         -> assets.id
    alerts.related_asset_id       -> assets.id
    alerts.related_finding_id     -> findings.id
    risk_scores.scan_run_id       -> scan_runs.id
    observations.scan_run_id      -> scan_runs.id

Already correct (no change):
    certificates.asset_id     -> CASCADE (enrichment model)
    endpoints.asset_id        -> CASCADE (enrichment model)
    relationships.source/target_asset_id -> CASCADE (risk model)
    issue_findings.issue_id/finding_id   -> CASCADE (issues model)
    issue_activities.issue_id            -> CASCADE (issues model)

Revision ID: 017
Revises: 016
Create Date: 2026-03-15
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


# Each entry: (constraint_name, table, column, ref_table, ref_column, ondelete)
# PostgreSQL auto-generates FK names as "{table}_{column}_fkey".
FK_CHANGES = [
    # ── CASCADE: non-nullable children of assets ─────────────────
    ("services_asset_id_fkey", "services", ["asset_id"], "assets", ["id"], "CASCADE"),
    ("findings_asset_id_fkey", "findings", ["asset_id"], "assets", ["id"], "CASCADE"),
    ("events_asset_id_fkey", "events", ["asset_id"], "assets", ["id"], "CASCADE"),

    # ── CASCADE: non-nullable children of tenants ────────────────
    ("assets_tenant_id_fkey", "assets", ["tenant_id"], "tenants", ["id"], "CASCADE"),
    ("seeds_tenant_id_fkey", "seeds", ["tenant_id"], "tenants", ["id"], "CASCADE"),

    # ── CASCADE: non-nullable children of findings ───────────────
    ("tickets_finding_id_fkey", "tickets", ["finding_id"], "findings", ["id"], "CASCADE"),

    # ── CASCADE: non-nullable children of scan_runs ──────────────
    ("phase_results_scan_run_id_fkey", "phase_results", ["scan_run_id"], "scan_runs", ["id"], "CASCADE"),

    # ── SET NULL: nullable references to assets ──────────────────
    ("observations_asset_id_fkey", "observations", ["asset_id"], "assets", ["id"], "SET NULL"),
    ("alerts_related_asset_id_fkey", "alerts", ["related_asset_id"], "assets", ["id"], "SET NULL"),

    # ── SET NULL: nullable references to findings ────────────────
    ("alerts_related_finding_id_fkey", "alerts", ["related_finding_id"], "findings", ["id"], "SET NULL"),

    # ── SET NULL: nullable references to scan_runs ───────────────
    ("risk_scores_scan_run_id_fkey", "risk_scores", ["scan_run_id"], "scan_runs", ["id"], "SET NULL"),
    ("observations_scan_run_id_fkey", "observations", ["scan_run_id"], "scan_runs", ["id"], "SET NULL"),
]


def upgrade() -> None:
    for constraint_name, table, columns, ref_table, ref_columns, ondelete in FK_CHANGES:
        op.drop_constraint(constraint_name, table, type_="foreignkey")
        op.create_foreign_key(
            constraint_name,
            table,
            ref_table,
            columns,
            ref_columns,
            ondelete=ondelete,
        )


def downgrade() -> None:
    # Restore original FKs without ondelete action (the original state).
    for constraint_name, table, columns, ref_table, ref_columns, _ondelete in FK_CHANGES:
        op.drop_constraint(constraint_name, table, type_="foreignkey")
        op.create_foreign_key(
            constraint_name,
            table,
            ref_table,
            columns,
            ref_columns,
            # No ondelete -- restores the original RESTRICT/NO ACTION default.
        )
