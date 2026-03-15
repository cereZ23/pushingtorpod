#!/bin/sh
set -e

# EASM API Entrypoint Script
# Runs database migrations then starts the uvicorn server.
# Separating concerns ensures clear error reporting when migrations fail.

echo "==> Running database migrations..."
if alembic upgrade head; then
    echo "==> Migrations completed successfully."
else
    echo "==> ERROR: Database migration failed (exit code: $?)." >&2
    echo "==> The API will NOT start until migrations succeed." >&2
    echo "==> Check the migration files and database connectivity." >&2
    exit 1
fi

echo "==> Starting uvicorn server..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers "${API_WORKERS:-1}" \
    --log-level "${LOG_LEVEL:-info}" \
    --proxy-headers \
    --forwarded-allow-ips='172.16.0.0/12'
