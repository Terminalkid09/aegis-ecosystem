#!/bin/sh
set -eu

cd /opt/aegis/kraken

if [ -f /var/lib/aegis/kraken/images.ok ] && [ "${AEGIS_FORCE_BUILD:-0}" != "1" ]; then
    exit 0
fi

docker compose --env-file /etc/aegis/kraken.env build
install -d -m 0755 /var/lib/aegis/kraken
touch /var/lib/aegis/kraken/images.ok
