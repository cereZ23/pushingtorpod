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

    while True:
        # Fetch a batch of findings whose evidence is a JSON text scalar.
        # json_typeof returns 'string' for JSON text scalars, which is the
        # problematic case (double-encoded dicts, or plain strings).
        rows = conn.execute(
            sa.text("""
                SELECT id, evidence::text AS evidence_text
                FROM findings
                WHERE evidence IS NOT NULL
                  AND json_typeof(evidence) = 'string'
                LIMIT :batch_size
            """),
            {"batch_size": BATCH_SIZE},
        ).fetchall()

        if not rows:
            break

        for row in rows:
            fid = row[0]
            raw_text = row[1]  # The unwrapped Python string

            # Try to parse the string as JSON — it might be a
            # double-encoded dict like '{"key": "val"}'.
            try:
                parsed = json.loads(raw_text)
            except (json.JSONDecodeError, TypeError):
                # Not valid JSON at all — wrap it.
                parsed = {"raw": raw_text}

            # If the parsed result is a dict or list, use it directly.
            # Otherwise (str, int, float, bool, None) wrap in {"raw": ...}.
            if not isinstance(parsed, (dict, list)):
                parsed = {"raw": parsed}

            conn.execute(
                sa.text(
                    "UPDATE findings SET evidence = :evidence::json WHERE id = :fid"
                ),
                {"evidence": json.dumps(parsed), "fid": fid},
            )
            total_updated += 1

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
