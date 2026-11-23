#!/bin/sh
set -eu

cd /opt/aegis/server

# The unit starts before Compose. If another service now owns the dashboard
# port, select a free one before the stack is brought up. This keeps the
# recorded env, the published port and ak url in sync.
if [ -x /usr/local/lib/aegis/ensure-ui-port.sh ]; then
    /usr/local/lib/aegis/ensure-ui-port.sh || exit 1
fi

if [ -f /var/lib/aegis/server/images.ok ] && [ "${AEGIS_FORCE_BUILD:-0}" != "1" ]; then
    exit 0
fi

docker compose --env-file /etc/aegis/server.env build
install -d -m 0755 /var/lib/aegis/server
touch /var/lib/aegis/server/images.ok
