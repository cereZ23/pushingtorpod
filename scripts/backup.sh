#!/bin/bash
# =============================================================================
# PostgreSQL Backup Script for EASM Platform
# =============================================================================
# Usage:
#   ./scripts/backup.sh              # Run backup
#   ./scripts/backup.sh --restore <file>  # Restore from backup
#
# Crontab (daily at 3 AM, 7-day retention):
#   0 3 * * * /opt/easm/scripts/backup.sh >> /var/log/easm-backup.log 2>&1
# =============================================================================

set -euo pipefail

BACKUP_DIR="${EASM_BACKUP_DIR:-/opt/easm/backups/postgres}"
RETENTION_DAYS="${EASM_BACKUP_RETENTION_DAYS:-7}"
CONTAINER_NAME="easm-postgres"
DB_NAME="easm"
DB_USER="easm"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ─── Restore mode ───────────────────────────────────────────────
if [ "${1:-}" = "--restore" ]; then
    RESTORE_FILE="${2:-}"
    if [ -z "$RESTORE_FILE" ] || [ ! -f "$RESTORE_FILE" ]; then
        echo "Usage: $0 --restore <backup-file.dump>"
        echo ""
        echo "Available backups:"
        ls -lht "${BACKUP_DIR}"/easm_*.dump 2>/dev/null || echo "  (none found in ${BACKUP_DIR})"
        exit 1
    fi

    echo "WARNING: This will DROP and recreate the '${DB_NAME}' database."
    echo "File: ${RESTORE_FILE}"
    read -rp "Continue? [y/N] " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi

    echo "$(date): Restoring from ${RESTORE_FILE}..."
    cat "${RESTORE_FILE}" | docker exec -i "${CONTAINER_NAME}" \
        pg_restore -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists --no-owner 2>&1 || true

    echo "$(date): Restore complete. Verify data integrity manually."
    exit 0
fi

# ─── Backup mode ────────────────────────────────────────────────
mkdir -p "${BACKUP_DIR}"

# Verify postgres container is running
if ! docker inspect "${CONTAINER_NAME}" --format='{{.State.Running}}' 2>/dev/null | grep -q true; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

BACKUP_FILE="${BACKUP_DIR}/easm_${TIMESTAMP}.dump"

echo "$(date): Starting backup..."

# pg_dump with custom format (compressed, supports selective restore)
docker exec "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -Fc "${DB_NAME}" > "${BACKUP_FILE}"

# Verify backup is not empty (minimum 1KB)
BACKUP_SIZE=$(stat -f%z "${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_FILE}" 2>/dev/null)
if [ "${BACKUP_SIZE}" -lt 1024 ]; then
    echo "ERROR: Backup file too small (${BACKUP_SIZE} bytes), likely failed." >&2
    rm -f "${BACKUP_FILE}"
    exit 1
fi

BACKUP_HUMAN=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "$(date): Backup created: ${BACKUP_FILE} (${BACKUP_HUMAN})"

# Delete backups older than retention period
DELETED=$(find "${BACKUP_DIR}" -name "easm_*.dump" -mtime +"${RETENTION_DAYS}" -print -delete | wc -l)
if [ "${DELETED}" -gt 0 ]; then
    echo "$(date): Deleted ${DELETED} backup(s) older than ${RETENTION_DAYS} days."
fi

# Summary
TOTAL=$(find "${BACKUP_DIR}" -name "easm_*.dump" | wc -l)
echo "$(date): Backup complete. ${TOTAL} backup(s) retained."
