#!/bin/sh
# Aegis DB Restore — uso manuale dell'operatore (MAI automatico).
# Uso: ./scripts/restore-db.sh <file-backup> [target_db]
# Il file può essere .sql.gz (chiaro) o .sql.gz.gpg (cifrato: serve
# BACKUP_PASSPHRASE). Senza I_CONFIRM_RESTORE=yes si rifiuta (anti-errori).
# I backup cifrati si decifrano SEMPRE su file temporaneo PRIMA di toccare il
# DB: l'MDC viene verificato per intero e un backup manomesso non ripristina
# nulla (GPG esce non-zero e `set -eu` abortisce).
set -eu

if [ "${1:-}" = "" ]; then
  echo "Uso: $0 <aegis_db_*.sql.gz[.enc]> [target_db]" >&2
  exit 2
fi
FILE="$1"
TARGET_DB="${2:-${DB_NAME:-aegis}}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
export PGPASSWORD="${PGPASSWORD:-}"

if [ ! -f "$FILE" ]; then
  echo "File non trovato: $FILE" >&2
  exit 2
fi
if [ "${I_CONFIRM_RESTORE:-}" != "yes" ]; then
  echo "REFUSING: imposta I_CONFIRM_RESTORE=yes per ripristinare su '$TARGET_DB'." >&2
  exit 3
fi

case "$FILE" in
  *.gpg)
    if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
      echo "Backup cifrato ma BACKUP_PASSPHRASE assente." >&2
      exit 2
    fi
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT INT TERM
    printf '%s' "$BACKUP_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
      --passphrase-fd 0 --decrypt -o "$WORK/restore.sql.gz" "$FILE"
    gunzip -c "$WORK/restore.sql.gz" | psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TARGET_DB"
    ;;
  *.gz)
    echo "WARNING: backup in chiaro." >&2
    gunzip -c "$FILE" | psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TARGET_DB"
    ;;
  *)
    echo "Estensione non riconosciuta (attesi .sql.gz o .sql.gz.gpg)." >&2
    exit 2
    ;;
esac
echo "Restore completato su '$TARGET_DB'."
