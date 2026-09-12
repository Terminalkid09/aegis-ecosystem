#!/bin/sh
# Aegis PKI backup — chiavi CA e manifest in archivio cifrato (post-audit).
# Eseguito dal container aegis-backup (cron) con /pki e /artifacts montati
# read-only e /backups scrivibile. BACKUP_PASSPHRASE OBBLIGATORIA: una CA
# in chiaro è compromissione totale — senza passphrase si rifiuta (fail-closed).
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups/pki}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
PKI_SRC="${PKI_SRC:-/pki}"
ARTIFACTS_SRC="${ARTIFACTS_SRC:-/artifacts}"

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  echo "REFUSING: BACKUP_PASSPHRASE obbligatoria per il backup PKI." >&2
  exit 2
fi
if [ ! -f "$PKI_SRC/ca.crt" ]; then
  echo "REFUSING: $PKI_SRC/ca.crt assente — PKI non inizializzata?" >&2
  exit 2
fi

mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

tar -czf "$WORK/pki-bundle.tar.gz" -C "$(dirname "$PKI_SRC")" "$(basename "$PKI_SRC")"
if [ -d "$ARTIFACTS_SRC" ]; then
  tar -czf "$WORK/artifacts.tar.gz" -C "$(dirname "$ARTIFACTS_SRC")" "$(basename "$ARTIFACTS_SRC")"
fi
BUNDLE="$WORK/bundle.tar"
tar -cf "$BUNDLE" -C "$WORK" pki-bundle.tar.gz artifacts.tar.gz

OUT="${BACKUP_DIR}/aegis_pki_${TIMESTAMP}.tar.gpg"
printf '%s' "$BACKUP_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
  --passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$OUT" "$BUNDLE"
chmod 600 "$OUT"
find "$BACKUP_DIR" -name "aegis_pki_*.tar.gpg" -mtime +"$RETENTION_DAYS" -delete
echo "PKI backup created (encrypted): $OUT ($(du -h "$OUT" | cut -f1))"
echo "Restore: BACKUP_PASSPHRASE=... ./scripts/restore-pki.sh <file> <destdir>"
