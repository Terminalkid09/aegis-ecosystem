#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Disaster-recovery drill: encrypted PostgreSQL restore + PKI/artifact restore.
# It uses disposable databases and a temporary staging directory; it never
# restores into the live database and never writes to the live PKI volume.
#
# Usage:
#   BACKUP_PASSPHRASE='...' ./scripts/dr_drill.sh
#   ./scripts/dr_drill.sh --skip-db          # PKI-only, no PostgreSQL client
#   ./scripts/dr_drill.sh --skip-pki         # DB-only
#
# Required for the DB part: pg_dump/pg_restore, psql, createdb/dropdb and a
# reachable disposable PostgreSQL (the same environment as test-restore.sh).
# Required for the PKI part: gpg and tar.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_DB=0
SKIP_PKI=0
for arg in "$@"; do
  case "$arg" in
    --skip-db) SKIP_DB=1 ;;
    --skip-pki) SKIP_PKI=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    BACKUP_PASSPHRASE="$(openssl rand -hex 32)"
  else
    BACKUP_PASSPHRASE="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  echo "Using an ephemeral BACKUP_PASSPHRASE for this drill (not exported)."
fi
export BACKUP_PASSPHRASE

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/dist/drills}"
mkdir -p "$EVIDENCE_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE="$EVIDENCE_DIR/dr-$STAMP.json"
DB_RESULT="skipped"
PKI_RESULT="skipped"

if [ "$SKIP_DB" -eq 1 ] && [ "$SKIP_PKI" -eq 1 ]; then
  echo "REFUSING: both drills are skipped; nothing would be verified" >&2
  exit 2
fi

if [ "$SKIP_DB" -eq 0 ]; then
  if ! command -v psql >/dev/null 2>&1; then
    echo "psql is required for the database drill; use --skip-db to run PKI only" >&2
    exit 2
  fi
  echo "== encrypted PostgreSQL backup/restore =="
  bash "$ROOT/scripts/test-restore.sh"
  DB_RESULT="passed"
fi

if [ "$SKIP_PKI" -eq 0 ]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required for the PKI drill" >&2
    exit 2
  fi
  echo "== encrypted PKI/artifact backup/restore =="
  mkdir -p "$TMP/pki" "$TMP/artifacts" "$TMP/backups"
  # A harmless CA fixture proves the archive/decrypt/extract path. A real
  # operator drill should point PKI_SRC/ARTIFACTS_SRC at a copy of the live
  # volumes, never at the live mount itself.
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'drill-fixture' \
    '-----END CERTIFICATE-----' > "$TMP/pki/ca.crt"
  printf '%s\n' 'artifact-fixture' > "$TMP/artifacts/README.txt"
  PKI_SRC="$TMP/pki" \
  ARTIFACTS_SRC="$TMP/artifacts" \
  BACKUP_DIR="$TMP/backups" \
    bash "$ROOT/scripts/backup-pki.sh"
  PKI_FILE="$(find "$TMP/backups" -maxdepth 1 -type f -name 'aegis_pki_*.tar.gpg' | sort | tail -1)"
  test -n "$PKI_FILE"
  I_CONFIRM_RESTORE=yes BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE" \
    bash "$ROOT/scripts/restore-pki.sh" "$PKI_FILE" "$TMP/restored"
  test -s "$TMP/restored/pki/ca.crt"
  test -s "$TMP/restored/artifacts/README.txt"
  PKI_RESULT="passed"
fi

cat > "$EVIDENCE" <<JSON
{
  "schema": "aegis-dr-drill-v1",
  "timestamp_utc": "$STAMP",
  "database_encrypted_restore": "$DB_RESULT",
  "pki_encrypted_restore": "$PKI_RESULT",
  "disposable_targets": true,
  "passed": $([ "$DB_RESULT" != "failed" ] && [ "$PKI_RESULT" != "failed" ] && echo true || echo false)
}
JSON
echo "DR drill evidence: $EVIDENCE"
echo "PASS: encrypted backup/restore drill ($([ "$DB_RESULT" = skipped ] && echo 'DB skipped' || echo 'DB restored'); $([ "$PKI_RESULT" = skipped ] && echo 'PKI skipped' || echo 'PKI restored'))"
