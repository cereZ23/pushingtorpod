"""Backfill fingerprint for existing findings that lack one.

Revision ID: 008
Revises: 007
Create Date: 2026-02-25

"""
from alembic import op
import sqlalchemy as sa
import hashlib

# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def _compute_fp(tenant_id, asset_identifier, template_id, matcher_name, source):
    parts = [
        str(tenant_id),
        (asset_identifier or "").strip().lower(),
        (template_id or "").strip().lower(),
        (matcher_name or "").strip().lower(),
        (source or "nuclei").strip().lower(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def upgrade() -> None:
    conn = op.get_bind()

    # Add matcher_name column if it doesn't exist yet
    inspector = sa.inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("findings")]
    if "matcher_name" not in columns:
        op.add_column("findings", sa.Column("matcher_name", sa.String(255), nullable=True))

    # Fetch findings that have no fingerprint yet
    rows = conn.execute(sa.text("""
        SELECT f.id, f.template_id, f.matcher_name, f.source,
               a.identifier, a.tenant_id
        FROM findings f
        JOIN assets a ON a.id = f.asset_id
        WHERE f.fingerprint IS NULL
    """)).fetchall()

    if not rows:
        return

    # Compute fingerprints and update in batches
    updates = []
    seen_fps = set()
    for row in rows:
        fid, template_id, matcher_name, source, identifier, tenant_id = row
        fp = _compute_fp(tenant_id, identifier, template_id, matcher_name, source)

        # Handle collisions: if two findings map to the same fingerprint,
        # keep only the first and append a suffix to make subsequent ones unique
        original_fp = fp
        counter = 0
        while fp in seen_fps:
            counter += 1
            fp = hashlib.sha256(f"{original_fp}:{counter}".encode()).hexdigest()

        seen_fps.add(fp)
        updates.append({"fid": fid, "fp": fp})

    # Batch update
    for upd in updates:
        conn.execute(
            sa.text("UPDATE findings SET fingerprint = :fp WHERE id = :fid"),
            upd,
        )


def downgrade() -> None:
    # Downgrade is handled by migration 007 which drops the column entirely
    pass
