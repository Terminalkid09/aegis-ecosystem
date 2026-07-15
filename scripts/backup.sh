#!/bin/bash
# Kraken backup script — exports PostgreSQL database and configuration
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/kraken_backup_${TIMESTAMP}.sql.gz"
CONFIG_BACKUP="${BACKUP_DIR}/kraken_config_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "=== Kraken Backup: $(date) ==="

# Database backup
echo "Backing up PostgreSQL database..."
PGPASSWORD="${DB_PASSWORD:-kraken_pass}" pg_dump \
    -h "${DB_HOST:-localhost}" \
    -U "${DB_USER:-kraken}" \
    -d "${DB_NAME:-krakendb}" \
    --no-owner \
    --no-acl \
    | gzip > "$BACKUP_FILE"
echo "Database backup: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

# Configuration backup
echo "Backing up configuration files..."
tar czf "$CONFIG_BACKUP" \
    -C /app .env 2>/dev/null || true
tar czf "$CONFIG_BACKUP" \
    -C /app/data reports plugins 2>/dev/null || true
echo "Config backup: $CONFIG_BACKUP"

# Cleanup backups older than 30 days
find "$BACKUP_DIR" -name "kraken_backup_*.sql.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "kraken_config_*.tar.gz" -mtime +30 -delete

echo "=== Backup complete ==="
