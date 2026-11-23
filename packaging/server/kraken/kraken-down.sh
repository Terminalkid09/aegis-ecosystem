#!/bin/sh
set -eu

cd /opt/aegis/kraken
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo 0)"

exec docker compose --env-file /etc/aegis/kraken.env down
