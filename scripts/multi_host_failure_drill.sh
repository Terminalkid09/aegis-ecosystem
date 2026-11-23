#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# True multi-host failover drill. It does not kill a local replica and does not
# pretend a Compose stack is a cluster: the operator triggers the managed
# PostgreSQL/Redis failover out of band while this script records role/master
# changes, Brain readiness and the lost-event counters.
#
# Required:
#   BRAIN_URLS=https://brain-a.example,https://brain-b.example
#   PG_MEMBERS='postgresql://...@pg-a/aegis,postgresql://...@pg-b/aegis'
#   or REDIS_SENTINELS='sentinel-a:26379,sentinel-b:26379'
# Optional:
#   REDIS_MASTER_NAME=aegis-master
#   REDIS_SENTINEL_PASSWORD=...
#   CURL_INSECURE=0|1 (default 1 for the lab CA)
#
# Usage:
#   ./scripts/multi_host_failure_drill.sh --yes
#   # In another terminal, trigger the managed failover.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRAIN_URLS="${BRAIN_URLS:-}"
PG_MEMBERS="${PG_MEMBERS:-}"
REDIS_SENTINELS="${REDIS_SENTINELS:-}"
REDIS_MASTER_NAME="${REDIS_MASTER_NAME:-aegis-master}"
CURL_INSECURE="${CURL_INSECURE:-1}"
TIMEOUT="${TIMEOUT:-600}"
INTERVAL="${INTERVAL:-5}"
YES=0
[ "${1:-}" = "--yes" ] && YES=1
if [ "$YES" -ne 1 ]; then
  echo "REFUSING: re-run with --yes after you have the external failover command ready." >&2
  exit 3
fi
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
IFS=',' read -r -a BRAINS <<< "$BRAIN_URLS"
IFS=',' read -r -a PG_DSNS <<< "$PG_MEMBERS"
IFS=',' read -r -a SENTINELS <<< "$REDIS_SENTINELS"
[ "${#BRAINS[@]}" -ge 2 ] || { echo 'BRAIN_URLS needs two or more URLs' >&2; exit 2; }
if [ "${#PG_DSNS[@]}" -lt 2 ] && [ "${#SENTINELS[@]}" -lt 2 ]; then
  echo 'set PG_MEMBERS or REDIS_SENTINELS (two or more members)' >&2
  exit 2
fi
[ "${#PG_DSNS[@]}" -lt 2 ] || command -v psql >/dev/null || {
  echo 'psql is required for PG_MEMBERS' >&2; exit 2;
}
[ "${#SENTINELS[@]}" -lt 2 ] || command -v redis-cli >/dev/null || {
  echo 'redis-cli is required for REDIS_SENTINELS' >&2; exit 2;
}
export PGCONNECT_TIMEOUT=3
export REDISCLI_AUTH="${REDIS_SENTINEL_PASSWORD:-}"

curl_health() {
  if [ "$CURL_INSECURE" = "1" ]; then
    curl -ksSf --max-time 10 "$1/health/ready" >/dev/null
  else
    curl -fsS --max-time 10 "$1/health/ready" >/dev/null
  fi
}

all_ready() {
  local url
  for url in "${BRAINS[@]}"; do
    curl_health "$url" || return 1
  done
}

lost_total() {
  local url total=0 value
  for url in "${BRAINS[@]}"; do
    value="$(curl -ksSf --max-time 10 "$url/metrics" 2>/dev/null \
      | awk '$1 == "aegis_events_lost_total" {sum += $NF} END {print sum + 0}')" \
      || { echo "cannot read metrics from $url" >&2; return 1; }
    total=$((total + value))
  done
  echo "$total"
}

pg_states() {
  local out=()
  local dsn state
  for dsn in "${PG_DSNS[@]}"; do
    state="$(psql "$dsn" -Atc 'select case when pg_is_in_recovery() then $$replica$$ else $$primary$$ end' 2>/dev/null || echo unknown)"
    out+=("$state")
  done
  printf '%s\n' "${out[*]}"
}

redis_master() {
  local sentinel host port value
  for sentinel in "${SENTINELS[@]}"; do
    host="${sentinel%:*}"
    port="${sentinel##*:}"
    value="$(redis-cli -h "$host" -p "$port" \
      sentinel get-master-addr-by-name "$REDIS_MASTER_NAME" 2>/dev/null \
      | paste -sd: -)"
    if [ -n "$value" ]; then echo "$value"; return 0; fi
  done
  return 1
}

pg_before="$(pg_states)"
redis_before="$(redis_master || true)"
lost_before="$(lost_total)"
all_ready || { echo "Brain URLs are not all ready before the drill" >&2; exit 1; }

echo "Before: pg=[$pg_before] redis-master=[$redis_before]"
echo ">>> Trigger the external PostgreSQL/Redis failover now. Waiting up to ${TIMEOUT}s. <<<"
changed=0
deadline=$((SECONDS + TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
  pg_now="$(pg_states)"
  redis_now="$(redis_master || true)"
  if [ "$pg_now" != "$pg_before" ] || [ "$redis_now" != "$redis_before" ]; then
    changed=1
    break
  fi
  sleep "$INTERVAL"
done
[ "$changed" -eq 1 ] || { echo "No PG/Redis role change observed; failover was not triggered" >&2; exit 1; }
echo "After trigger: pg=[$pg_now] redis-master=[$redis_now]"

ready_deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$ready_deadline" ]; do
  all_ready && break
  sleep "$INTERVAL"
done
if ! all_ready; then
  echo "Brain URLs did not all recover readiness after failover" >&2
  exit 1
fi
lost_after="$(lost_total)"
if [ "$lost_after" -gt "$lost_before" ]; then
  echo "Lost-event counter increased: before=$lost_before after=$lost_after" >&2
  exit 1
fi

OUT="$ROOT/dist/drills"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE="$OUT/multihost-$STAMP.json"
cat > "$EVIDENCE" <<JSON
{
  "schema": "aegis-multihost-failover-v1",
  "timestamp_utc": "$STAMP",
  "brain_urls": ${#BRAINS[@]},
  "pg_members_configured": $([ "${#PG_DSNS[@]}" -ge 2 ] && echo true || echo false),
  "redis_sentinels_configured": $([ "${#SENTINELS[@]}" -ge 2 ] && echo true || echo false),
  "pg_before": "$pg_before",
  "pg_after": "$pg_now",
  "redis_master_before": "$redis_before",
  "redis_master_after": "$redis_now",
  "lost_before": $lost_before,
  "lost_after": $lost_after,
  "triggered_by": "external_operator",
  "passed": true
}
JSON
echo "Multi-host failover evidence: $EVIDENCE"
echo "PASS: external PG/Redis failover observed, all Brains ready, no lost-event increase."
