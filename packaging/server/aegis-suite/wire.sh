#!/bin/sh
# Idempotent cross-stack wiring for aegis-suite. This is installed by the
# metapackage and also called by the aegis/kraken postinst when the suite is
# present, because dpkg may configure the metapackage before its dependencies.
set -eu

SERVER_ENV=/etc/aegis/server.env
KRAKEN_ENV=/etc/aegis/kraken.env

[ -s "$SERVER_ENV" ] && [ -s "$KRAKEN_ENV" ] || exit 0

rand() {
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

get_env() {
    key="$1"
    file="$2"
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

set_env() {
    key="$1"
    value="$2"
    file="$3"
    if grep -q "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

api_key="$(get_env AEGIS_API_KEY "$SERVER_ENV")"
[ -n "$api_key" ] || exit 0

# Prefer an existing value, so a package upgrade does not rotate a working
# integration. If neither side has one, generate it once and use it on both.
sso_secret="$(get_env KRAKEN_SSO_SECRET "$KRAKEN_ENV")"
[ -n "$sso_secret" ] || sso_secret="$(get_env KRAKEN_SSO_SECRET "$SERVER_ENV")"
[ -n "$sso_secret" ] || sso_secret="$(rand 32)"

ingest_secret="$(get_env KRAKEN_INGEST_SECRET "$KRAKEN_ENV")"
[ -n "$ingest_secret" ] || ingest_secret="$(get_env KRAKEN_INGEST_SECRET "$SERVER_ENV")"
[ -n "$ingest_secret" ] || ingest_secret="$(rand 32)"

set_env KRAKEN_SSO_ENABLED true "$SERVER_ENV"
set_env KRAKEN_SSO_SECRET "$sso_secret" "$SERVER_ENV"
set_env KRAKEN_INGEST_ENABLED true "$SERVER_ENV"
set_env KRAKEN_INGEST_SECRET "$ingest_secret" "$SERVER_ENV"

set_env KRAKEN_SSO_ENABLED true "$KRAKEN_ENV"
set_env KRAKEN_SSO_SECRET "$sso_secret" "$KRAKEN_ENV"
set_env KRAKEN_INGEST_ENABLED true "$KRAKEN_ENV"
set_env KRAKEN_INGEST_SECRET "$ingest_secret" "$KRAKEN_ENV"
set_env KRAKEN_INGEST_URL http://aegis-brain:8000 "$KRAKEN_ENV"
set_env KRAKEN_INGEST_KEY "$api_key" "$KRAKEN_ENV"
set_env KRAKEN_PUBLIC_BASE_PATH /kraken "$KRAKEN_ENV"

chmod 0600 "$SERVER_ENV" "$KRAKEN_ENV"
chown root:root "$SERVER_ENV" "$KRAKEN_ENV"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl try-restart aegis.service kraken.service >/dev/null 2>&1 || true
fi

exit 0
