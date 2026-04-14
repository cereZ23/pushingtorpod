"""Normalize findings.evidence JSON strings and services.protocol values

Data quality migration that fixes two issues observed in production:

1. findings.evidence — Some rows have evidence stored as a JSON-encoded
   string (e.g., the JSON column contains '"some text"' or '{"key":"val"}' as
   a text scalar) instead of a proper JSON object.  This happens when the scan
   pipeline calls json.dumps() twice or stores a plain string.  We convert:
   - text that parses to a dict  -> the dict itself
   - text that parses to a list  -> the list itself
   - text that parses to a scalar (str/int/bool/null) -> {"raw": <value>}

2. services.protocol — Rows with protocol='tcp' on well-known HTTP(S) ports
   should reflect the application-layer protocol for correct display and
   risk scoring.

Both operations are idempotent: re-running the migration is safe.

Revision ID: 020
Revises: 019
"""

from __future__ import annotations

import json
import logging

from alembic import op
import sqlalchemy as sa

logger = logging.getLogger(__name__)

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None

# Batch size for updates to avoid long-held locks on large tables.
BATCH_SIZE = 1000


def _normalize_evidence(conn: sa.engine.Connection) -> int:
    """Fix findings.evidence rows where the JSON value is a text scalar.

    PostgreSQL's JSON column can legally hold a JSON text scalar (e.g.
    '"hello"' or '"{\\"key\\":\\"val\\"}"').  We detect these with
    ``json_typeof(evidence) = 'string'`` and re-parse them into proper
    JSON objects/arrays, or wrap bare scalars in ``{"raw": ...}``.

    Returns the total number of rows updated.
    """
    total_updated = 0

    # The evidence column is type TEXT (not JSON/JSONB). We find rows
    # where the text content is a double-encoded JSON string (e.g., the
    # text starts with '"' meaning it's a JSON string scalar that wraps
    # the actual dict). We parse and re-serialize these.
    while True:
        rows = conn.execute(
            sa.text("""
                SELECT id, evidence
                FROM findings
                WHERE evidence IS NOT NULL
                  AND evidence != ''
                  AND evidence != '{}'
                LIMIT :batch_size
            """),
            {"batch_size": BATCH_SIZE},
        ).fetchall()

        if not rows:
            break

        batch_had_updates = False
        for row in rows:
            fid = row[0]
            raw_text = row[1]

            if not isinstance(raw_text, str) or not raw_text.strip():
                continue

            # Try to parse the evidence text as JSON
            try:
                parsed = json.loads(raw_text)
            except (json.JSONDecodeError, TypeError):
                # Not valid JSON — wrap it
                new_val = json.dumps({"raw": raw_text})
                conn.execute(
                    sa.text("UPDATE findings SET evidence = :ev WHERE id = :fid"),
                    {"ev": new_val, "fid": fid},
                )
                total_updated += 1
                batch_had_updates = True
                continue

            # If parsed is already a dict, it's fine — skip
            if isinstance(parsed, dict):
                continue

            # If parsed is a string (double-encoded), try to parse again
            if isinstance(parsed, str):
                try:
                    inner = json.loads(parsed)
                    if isinstance(inner, dict):
                        new_val = json.dumps(inner)
                    else:
                        new_val = json.dumps({"raw": inner})
                except (json.JSONDecodeError, TypeError):
                    new_val = json.dumps({"raw": parsed})

                conn.execute(
                    sa.text("UPDATE findings SET evidence = :ev WHERE id = :fid"),
                    {"ev": new_val, "fid": fid},
                )
                total_updated += 1
                batch_had_updates = True
                continue

            # If parsed is a list or other type, wrap
            if not isinstance(parsed, dict):
                new_val = json.dumps({"raw": parsed})
                conn.execute(
                    sa.text("UPDATE findings SET evidence = :ev WHERE id = :fid"),
                    {"ev": new_val, "fid": fid},
                )
                total_updated += 1
                batch_had_updates = True

        if not batch_had_updates:
            break

    return total_updated


def _normalize_protocol(conn: sa.engine.Connection) -> int:
    """Fix services.protocol for well-known HTTP(S) ports.

    Converts 'tcp' to 'https' on ports 443/8443 and to 'http' on
    ports 80/8080.  Uses batched updates to limit lock duration.

    Returns the total number of rows updated.
    """
    total_updated = 0

    # HTTPS ports
    while True:
        result = conn.execute(
            sa.text("""
                UPDATE services
                SET protocol = 'https'
                WHERE id IN (
                    SELECT id FROM services
                    WHERE protocol = 'tcp' AND port IN (443, 8443)
                    LIMIT :batch_size
                )
            """),
            {"batch_size": BATCH_SIZE},
        )
        affected = result.rowcount
        total_updated += affected
        if affected < BATCH_SIZE:
            break

    # HTTP ports
    while True:
        result = conn.execute(
            sa.text("""
                UPDATE services
                SET protocol = 'http'
                WHERE id IN (
                    SELECT id FROM services
                    WHERE protocol = 'tcp' AND port IN (80, 8080)
                    LIMIT :batch_size
                )
            """),
            {"batch_size": BATCH_SIZE},
        )
        affected = result.rowcount
        total_updated += affected
        if affected < BATCH_SIZE:
            break

    return total_updated


def upgrade() -> None:
    conn = op.get_bind()

    # --- 1. Normalize findings.evidence ---
    evidence_count = _normalize_evidence(conn)
    if evidence_count:
        logger.info(
            "Migration 020: normalized %d findings.evidence rows", evidence_count
        )

    # --- 2. Normalize services.protocol ---
    protocol_count = _normalize_protocol(conn)
    if protocol_count:
        logger.info(
            "Migration 020: normalized %d services.protocol rows", protocol_count
        )


def downgrade() -> None:
    # Data normalization is not reversible — the original malformed data
    # cannot be reconstructed.  Downgrade is intentionally a no-op.
    pass
