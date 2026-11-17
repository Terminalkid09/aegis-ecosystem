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

# Cifratura at-rest AUTENTICATA (GPG simmetrico AES256 + MDC integrity).
# Niente AES-CBC nudo (malleabile) e niente `openssl enc` AEAD (non
# supportato dai build minimali). BACKUP_PASSPHRASE obbligatoria in prod;
# senza, il backup resta in chiaro e lo si dichiara nel log.
if [ -n "${BACKUP_PASSPHRASE:-}" ]; then
  printf '%s' "$BACKUP_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --symmetric --cipher-algo AES256 \
    -o "${FILEPATH}.gpg" "$FILEPATH" && rm -f "$FILEPATH"
  echo "Backup created (encrypted, AES256+MDC): ${FILEPATH}.gpg ($(du -h "${FILEPATH}.gpg" | cut -f1))"
  echo "Restore: ./scripts/restore-db.sh <file>.gpg [db]"
else
  echo "WARNING: BACKUP_PASSPHRASE non impostata — backup IN CHIARO: $FILEPATH ($(du -h "$FILEPATH" | cut -f1))"
fi

# Rotate old backups (sia .gz che .gz.gpg)
find "$BACKUP_DIR" \( -name "aegis_db_*.sql.gz" -o -name "aegis_db_*.sql.gz.gpg" \) -mtime +$RETENTION_DAYS -delete
echo "Old backups (>${RETENTION_DAYS} days) cleaned."
