#!/usr/bin/env bash
# Load/soak wrapper for the configurable Docker limits.
#
# Prerequisites: the stack is already running (profile kraken or the default
# stack) and `.env` contains AGENT_ENROLL_KEY. This script captures `docker
# stats` around the existing pilot soak, which is the load generator; it does
# not start production services itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/check_compose_limits.py

before="$(mktemp)"
after="$(mktemp)"
trap 'rm -f "$before" "$after"' EXIT
docker stats --no-stream >"$before" || true

python3 scripts/pilot_soak.py \
  --agents "${AGENTS:-10}" \
  --duration "${DURATION:-300}" \
  --base "${AEGIS_BASE_URL:-http://127.0.0.1:8000}"

docker stats --no-stream >"$after" || true
printf '\nDocker stats before:\n'; sed -n '1,20p' "$before"
printf '\nDocker stats after:\n'; sed -n '1,20p' "$after"
printf '\nReview OOMKilled/restarts with: docker compose ps && docker inspect <container>\n'
