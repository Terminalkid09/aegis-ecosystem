#!/bin/bash
# Kraken restore script — decrypts and verifies a PostgreSQL backup.
set -euo pipefail

usage() {
    echo "Usage: $0 <backup_file.sql.gz.gpg>"
    echo "Requires BACKUP_PASSPHRASE_FILE and DB_PASSWORD/POSTGRES_PASSWORD."
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE" >&2
    exit 1
fi
if [ ! -f "${BACKUP_FILE}.sha256" ]; then
    echo "Error: Checksum not found: ${BACKUP_FILE}.sha256" >&2
    exit 1
fi
: "${BACKUP_PASSPHRASE_FILE:?BACKUP_PASSPHRASE_FILE must point to a 0400 passphrase file}"
if [ ! -r "$BACKUP_PASSPHRASE_FILE" ]; then
    echo "Error: Passphrase file not readable." >&2
    exit 1
fi

echo "=== Kraken Restore: $(date) ==="
echo "Restoring from: $BACKUP_FILE"

sha256sum -c "${BACKUP_FILE}.sha256"

read -r -p "This will DROP ALL EXISTING DATA in the database. Continue? (y/N) " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Restore cancelled."
    exit 0
fi

DB_HOST="${DB_HOST:-localhost}"
DB_USER="${DB_USER:-kraken}"
DB_NAME="${DB_NAME:-krakendb}"
DB_PASSWORD="${DB_PASSWORD:-${POSTGRES_PASSWORD:-}}"
: "${DB_PASSWORD:?DB_PASSWORD or POSTGRES_PASSWORD must be set}"

TMP_SQL=$(mktemp)
trap 'rm -f "$TMP_SQL"' EXIT
gpg --batch --yes --quiet --decrypt \
    --passphrase-file "$BACKUP_PASSPHRASE_FILE" \
    --output "$TMP_SQL" "$BACKUP_FILE"

echo "Dropping existing schema..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

echo "Restoring database..."
gunzip -c "$TMP_SQL" | PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -U "$DB_USER" \
    -d "$DB_NAME"

echo "=== Restore complete ==="
