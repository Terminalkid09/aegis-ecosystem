#!/bin/bash
# Kraken restore script — restores PostgreSQL database from a backup file
set -euo pipefail

usage() {
    echo "Usage: $0 <backup_file.sql.gz>"
    echo "Restores a Kraken PostgreSQL backup."
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "=== Kraken Restore: $(date) ==="
echo "Restoring from: $BACKUP_FILE"

# Confirm
read -p "This will DROP ALL EXISTING DATA in the database. Continue? (y/N) " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Restore cancelled."
    exit 0
fi

# Drop and recreate schema
echo "Dropping existing schema..."
PGPASSWORD="${DB_PASSWORD:-kraken_pass}" psql \
    -h "${DB_HOST:-localhost}" \
    -U "${DB_USER:-kraken}" \
    -d "${DB_NAME:-krakendb}" \
    -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Restore
echo "Restoring database..."
gunzip -c "$BACKUP_FILE" | PGPASSWORD="${DB_PASSWORD:-kraken_pass}" psql \
    -h "${DB_HOST:-localhost}" \
    -U "${DB_USER:-kraken}" \
    -d "${DB_NAME:-krakendb}"

echo "=== Restore complete ==="
