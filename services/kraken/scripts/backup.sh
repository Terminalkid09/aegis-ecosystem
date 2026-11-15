#!/bin/bash
# Kraken backup script — PostgreSQL + configuration, encrypted with GPG.
set -euo pipefail
umask 077

BACKUP_DIR="${BACKUP_DIR:-/backups}"
APP_DIR="${APP_DIR:-/app}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/kraken_backup_${TIMESTAMP}.sql.gz.gpg"
CONFIG_BACKUP="${BACKUP_DIR}/kraken_config_${TIMESTAMP}.tar.gz.gpg"

: "${BACKUP_PASSPHRASE_FILE:?BACKUP_PASSPHRASE_FILE must point to a 0400 passphrase file}"
if [ ! -r "$BACKUP_PASSPHRASE_FILE" ]; then
    echo "FATAL: passphrase file is not readable: $BACKUP_PASSPHRASE_FILE" >&2
    exit 1
fi

DB_HOST="${DB_HOST:-localhost}"
DB_USER="${DB_USER:-kraken}"
DB_NAME="${DB_NAME:-krakendb}"
DB_PASSWORD="${DB_PASSWORD:-${POSTGRES_PASSWORD:-}}"
: "${DB_PASSWORD:?DB_PASSWORD or POSTGRES_PASSWORD must be set}"

GPG_CMD=(gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
    --passphrase-file "$BACKUP_PASSPHRASE_FILE")

mkdir -p "$BACKUP_DIR"
DB_TMP=$(mktemp "${BACKUP_DIR}/.db.XXXXXX")
CONFIG_TMP=$(mktemp "${BACKUP_DIR}/.config.XXXXXX")
cleanup() {
    rm -f "$DB_TMP" "$CONFIG_TMP"
}
trap cleanup EXIT

echo "=== Kraken Backup: $(date) ==="

echo "Backing up PostgreSQL database..."
PGPASSWORD="$DB_PASSWORD" pg_dump \
    -h "$DB_HOST" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --no-owner \
    --no-acl \
    | gzip > "$DB_TMP"
"${GPG_CMD[@]}" --output "$BACKUP_FILE" "$DB_TMP"
sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
echo "Database backup: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

echo "Backing up configuration files..."
CONFIG_PATHS=()
for path in .env data reports plugins; do
    if [ -e "$APP_DIR/$path" ]; then
        CONFIG_PATHS+=("$path")
    fi
done
if [ "${#CONFIG_PATHS[@]}" -eq 0 ]; then
    echo "FATAL: no configuration paths found under $APP_DIR" >&2
    exit 1
fi
tar czf "$CONFIG_TMP" -C "$APP_DIR" "${CONFIG_PATHS[@]}"
"${GPG_CMD[@]}" --output "$CONFIG_BACKUP" "$CONFIG_TMP"
sha256sum "$CONFIG_BACKUP" > "${CONFIG_BACKUP}.sha256"
echo "Config backup: $CONFIG_BACKUP"

find "$BACKUP_DIR" -name "kraken_backup_*.gpg" -mtime +"$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -name "kraken_config_*.gpg" -mtime +"$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -name "kraken_*.gpg.sha256" -mtime +"$RETENTION_DAYS" -delete

echo "=== Backup complete ==="
