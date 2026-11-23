#!/bin/sh
# Aegis PKI restore — SOLO manuale (chiavi!). Estrae bundle cifrato in una
# directory di staging: l'operatore sposta poi i file nei volumi.
# Uso: BACKUP_PASSPHRASE=... ./scripts/restore-pki.sh <file.tar.gpg> <destdir>
set -eu

if [ "${1:-}" = "" ] || [ "${2:-}" = "" ]; then
  echo "Uso: $0 <aegis_pki_*.tar.enc> <destdir>" >&2
  exit 2
fi
FILE="$1"
DEST="$2"
if [ ! -f "$FILE" ]; then
  echo "File non trovato: $FILE" >&2
  exit 2
fi
if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  echo "BACKUP_PASSPHRASE assente." >&2
  exit 2
fi
if [ "${I_CONFIRM_RESTORE:-}" != "yes" ]; then
  echo "REFUSING: imposta I_CONFIRM_RESTORE=yes (chiavi CA in gioco)." >&2
  exit 3
fi

mkdir -p "$DEST"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
# Decifratura su file temporaneo: l'MDC è verificato per intero prima di
# estrarre qualsiasi cosa (bundle manomesso = exit non-zero, niente restore).
printf '%s' "$BACKUP_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
  --passphrase-fd 0 --decrypt -o "$WORK/bundle.tar" "$FILE"
tar -xf "$WORK/bundle.tar" -C "$WORK"
tar -xzf "$WORK/pki-bundle.tar.gz" -C "$DEST"
if [ -f "$WORK/artifacts.tar.gz" ]; then
  tar -xzf "$WORK/artifacts.tar.gz" -C "$DEST"
fi
chmod 700 "$DEST/pki" 2>/dev/null || true
echo "PKI ripristinata in staging: $DEST"
echo "Verifica: ls -la $DEST/pki && openssl x509 -in $DEST/pki/ca.crt -noout -subject -dates"
echo "Poi sposta in volume persistente e riavvia i servizi (OPERATIONS.md)."
