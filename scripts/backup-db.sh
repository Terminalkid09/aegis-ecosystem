#!/bin/bash
# Aegis DB Backup Script
# Run via cron or docker exec: 0 */6 * * * /scripts/backup-db.sh

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
DB_HOST="${DB_HOST:-aegis-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-aegis_db}"
DB_USER="${DB_USER:-aegis_user}"
PGPASS="${PGPASSWORD:-}"

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="aegis_db_${TIMESTAMP}.sql.gz"
FILEPATH="${BACKUP_DIR}/${FILENAME}"

export PGPASSWORD="$PGPASS"
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" --no-owner | gzip > "$FILEPATH"

echo "Backup created: $FILEPATH ($(du -h "$FILEPATH" | cut -f1))"

# Rotate old backups
find "$BACKUP_DIR" -name "aegis_db_*.sql.gz" -mtime +$RETENTION_DAYS -delete
echo "Old backups (>${RETENTION_DAYS} days) cleaned."
