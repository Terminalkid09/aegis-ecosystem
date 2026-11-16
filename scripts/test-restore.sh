#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Backup/restore round-trip against a disposable database pair.
#
# Why this exists: the backup scripts were only exercised by an operator at
# 3am, after something had already gone wrong. This test creates source and
# target databases with unique names, writes a probe row, runs the real
# backup-db.sh, restores with restore-db.sh, and verifies the row. It never
# touches an existing database.
#
# Required environment (defaults match docker compose):
#   DB_HOST, DB_PORT, DB_USER, PGPASSWORD, ADMIN_DB
# Optional:
#   BACKUP_PASSPHRASE   if set, exercises the GPG-encrypted branch
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
ADMIN_DB="${ADMIN_DB:-postgres}"
export PGPASSWORD="${PGPASSWORD:-}"

TMP_DIR="$(mktemp -d)"
SOURCE_DB="aegis_restore_src_$$"
TARGET_DB="aegis_restore_dst_$$"
BACKUP_DIR="${TMP_DIR}/backups"

cleanup() {
  dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" --if-exists "$TARGET_DB" >/dev/null 2>&1 || true
  dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" --if-exists "$SOURCE_DB" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$BACKUP_DIR"

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ADMIN_DB" \
  -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$SOURCE_DB\"" >/dev/null
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$SOURCE_DB" \
  -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE restore_probe (
    id integer PRIMARY KEY,
    value text NOT NULL
);
INSERT INTO restore_probe (id, value) VALUES (1, 'aegis-restore-ok');
SQL

BACKUP_DIR="$BACKUP_DIR" \
DB_NAME="$SOURCE_DB" \
DB_HOST="$DB_HOST" \
DB_PORT="$DB_PORT" \
DB_USER="$DB_USER" \
PGPASSWORD="$PGPASSWORD" \
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}" \
  "$ROOT_DIR/scripts/backup-db.sh"

BACKUP_FILE="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'aegis_db_*.sql.gz*' | sort | tail -1)"
if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
  echo "FAIL: backup-db.sh did not produce an archive" >&2
  exit 1
fi

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ADMIN_DB" \
  -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$TARGET_DB\"" >/dev/null
I_CONFIRM_RESTORE=yes \
DB_HOST="$DB_HOST" \
DB_PORT="$DB_PORT" \
DB_USER="$DB_USER" \
PGPASSWORD="$PGPASSWORD" \
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}" \
  "$ROOT_DIR/scripts/restore-db.sh" "$BACKUP_FILE" "$TARGET_DB"

VALUE="$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TARGET_DB" \
  -v ON_ERROR_STOP=1 -tAc "SELECT value FROM restore_probe WHERE id = 1")"
VALUE="${VALUE//[[:space:]]/}"
if [ "$VALUE" != "aegis-restore-ok" ]; then
  echo "FAIL: restored probe is '$VALUE', expected 'aegis-restore-ok'" >&2
  exit 1
fi

echo "PASS: backup/restore round-trip restored the probe row ($(basename "$BACKUP_FILE"))"
