#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Single-host HA failure drill. It proves that two Brain/Link replicas survive
# the loss of one replica and that readiness recovers. It does NOT claim
# PostgreSQL/Redis multi-host failover: those are external managed services or
# Sentinel/Patroni and require a separate lab (see docs/HA.md).
#
# Usage:
#   ./scripts/ha_failure_drill.sh --yes
#   AEGIS_BASE_URL=https://aegis.local ./scripts/ha_failure_drill.sh --yes
#
# The stack must already be running with the HA overlay:
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
#     -f docker-compose.ha.yml up -d --scale aegis-brain=2 --scale aegis-link=2
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${AEGIS_BASE_URL:-https://aegis.local}"
CURL_INSECURE="${CURL_INSECURE:-1}"
OUT_DIR="${EVIDENCE_DIR:-$ROOT/dist/drills}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE="$OUT_DIR/ha-$STAMP.json"
YES=0
[ "${1:-}" = "--yes" ] && YES=1
if [ "$YES" -ne 1 ]; then
  echo "REFUSING: this drill kills live replicas. Re-run with --yes." >&2
  exit 3
fi
mkdir -p "$OUT_DIR"
cd "$ROOT"

curl_health() {
  if [ "$CURL_INSECURE" = "1" ]; then
    curl -ksSf --max-time 10 "$BASE/health/ready" >/dev/null
  else
    curl -fsS --max-time 10 "$BASE/health/ready" >/dev/null
  fi
}

wait_ready() {
  local deadline=$((SECONDS + 90))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl_health; then return 0; fi
    sleep 3
  done
  return 1
}

brain_ids="$(docker compose ps -q aegis-brain 2>/dev/null || true)"
link_ids="$(docker compose ps -q aegis-link 2>/dev/null || true)"
brain_count="$(printf '%s\n' "$brain_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
link_count="$(printf '%s\n' "$link_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "$brain_count" -lt 2 ] || [ "$link_count" -lt 2 ]; then
  echo "REFUSING: need 2 running aegis-brain and 2 aegis-link replicas (got $brain_count/$link_count)." >&2
  echo "Start the HA overlay first; see docs/HA.md." >&2
  exit 2
fi
wait_ready || { echo "stack is not ready before the drill" >&2; exit 1; }

kill_and_recover() {
  local service="$1"
  local victim
  victim="$(docker compose ps -q "$service" | head -1)"
  test -n "$victim"
  echo "killing one $service replica: $victim"
  docker kill "$victim" >/dev/null
  # restart: unless-stopped restarts the same container. Wait for two running
  # replicas and then for readiness; a surviving replica can answer health
  # before the killed process has actually restarted.
  local deadline=$((SECONDS + 90))
  local count=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    count="$(docker compose ps -q "$service" | sed '/^$/d' | wc -l | tr -d ' ')"
    [ "$count" -ge 2 ] && break
    sleep 3
  done
  [ "$count" -ge 2 ] || { echo "$service did not return to 2 replicas (got $count)" >&2; return 1; }
  wait_ready || { echo "$service did not recover readiness after replica loss" >&2; return 1; }
}

echo "== Brain replica failure =="
kill_and_recover aegis-brain
echo "== Link replica failure =="
kill_and_recover aegis-link

cat > "$EVIDENCE" <<JSON
{
  "schema": "aegis-ha-drill-v1",
  "timestamp_utc": "$STAMP",
  "base": "$BASE",
  "brain_replicas": $brain_count,
  "link_replicas": $link_count,
  "brain_replica_loss_recovered": true,
  "link_replica_loss_recovered": true,
  "postgres_failover": "NOT_TESTED_SINGLE_HOST",
  "redis_failover": "NOT_TESTED_SINGLE_HOST",
  "passed": true,
  "limitations": "Single Docker host; true multi-host Postgres/Redis failover requires the external lab."
}
JSON
echo "HA drill evidence: $EVIDENCE"
echo "PASS: single-host replica failure drill; external Postgres/Redis failover not tested."
