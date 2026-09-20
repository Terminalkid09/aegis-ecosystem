#!/bin/sh
# Entrypoint aegis-brain:
# - Default (immagine, USER aegis): avvio diretto, nessun cambio utente.
# - Solo se il container parte come root (compose user override o volumi legacy
#   root-owned da installazioni precedenti): riassegna i volumi ad aegis e droppa.
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p /app/pki /app/artifacts
  chown -R aegis:aegis /app/pki /app/artifacts
  chmod 700 /app/pki
  exec gosu aegis "$@"
fi

exec "$@"