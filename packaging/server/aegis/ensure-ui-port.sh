#!/bin/sh
# Fail-safe for a stopped/rebooting stack: if the recorded dashboard port is
# occupied by something other than the running Aegis frontend, select a free
# port before Compose starts. Called by build-server.sh on every systemd start.
set -eu

ENV_FILE="${AK_SERVER_ENV:-/etc/aegis/server.env}"
HELPER="${AK_UI_HELPER:-/usr/local/lib/aegis/ui-port.sh}"

[ -s "$ENV_FILE" ] || exit 0
[ -r "$HELPER" ] || exit 0
. "$HELPER"

current="$(ak_get_env AEGIS_UI_PORT "$ENV_FILE")"
current="${current:-3000}"
ak_port_in_use "$current" || exit 0

# Docker may have restarted the previous Aegis frontend before the systemd unit.
# That is not a conflict; leave the configured port alone.
if command -v docker >/dev/null 2>&1; then
    own_container="$(docker ps --filter name=aegis-frontend --format '{{.Names}}' 2>/dev/null || true)"
    case "$own_container" in
        *aegis-frontend*) exit 0 ;;
    esac
fi

replacement="$(ak_find_free_ui_port "$current" 2>/dev/null || true)"
[ -n "$replacement" ] || {
    printf 'no free dashboard port in 3000-3099; set AEGIS_UI_PORT in %s\n' "$ENV_FILE" >&2
    exit 1
}

ak_set_env AEGIS_UI_PORT "$replacement" "$ENV_FILE"
ak_add_origins "$ENV_FILE" "http://localhost:$replacement"
chmod 0600 "$ENV_FILE" 2>/dev/null || true
printf 'dashboard port %s is busy; switched to %s\n' "$current" "$replacement" >&2
