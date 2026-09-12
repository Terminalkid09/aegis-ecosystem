#!/bin/bash
# Benchmark overhead sensore eBPF: N exec con e senza collector + loss check.
# Solo costrutti semplici (niente quoting annidato): robusto via docker.
set -u
cd /src
N=${1:-300}

echo "--- baseline senza sensore (${N} exec) ---"
T0=$(date +%s%N)
i=0
while [ $i -lt "$N" ]; do /bin/true; i=$((i + 1)); done
T1=$(date +%s%N)
BASE_MS=$(( (T1 - T0) / 1000000 ))
echo "baseline: ${BASE_MS}ms per ${N} exec"

echo "--- con sensore attivo ---"
if [ ! -d /sys/kernel/tracing ]; then mkdir -p /sys/kernel/tracing; fi
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
./aegis-collector --obj aegis_exec.bpf.o > /tmp/ev_bench.jsonl 2>/tmp/bench.log &
CPID=$!
sleep 2
if ! kill -0 $CPID 2>/dev/null; then echo "FATAL collector morto:"; cat /tmp/bench.log; exit 1; fi
T0=$(date +%s%N)
i=0
while [ $i -lt "$N" ]; do /bin/true; i=$((i + 1)); done
T1=$(date +%s%N)
SENS_MS=$(( (T1 - T0) / 1000000 ))
sleep 3
CPUTICKS=$(awk '{print $14+$15}' "/proc/$CPID/stat" 2>/dev/null || echo 0)
kill $CPID 2>/dev/null
wait 2>/dev/null || true
echo "con sensore: ${SENS_MS}ms per ${N} exec (collector ticks=${CPUTICKS})"

GOT_CREATED=$(grep '"comm":"true"' /tmp/ev_bench.jsonl | grep -c PROCESS_CREATED || true)
GOT_EXIT=$(grep '"comm":"true"' /tmp/ev_bench.jsonl | grep -c PROCESS_EXITED || true)
GOT=$(grep -c '"comm":"true"' /tmp/ev_bench.jsonl || true)
echo "exec /bin/true catturati: created=${GOT_CREATED}/${N} exited=${GOT_EXIT}/${N}"
if [ "$BASE_MS" -gt 0 ]; then
  OVERHEAD=$(awk "BEGIN {printf \"%.1f\", 100*($SENS_MS-$BASE_MS)/$BASE_MS}")
  echo "overhead wall-clock: ${OVERHEAD}%"
fi
FAIL=0
if [ "$GOT_CREATED" -lt "$N" ]; then echo "FAIL: exec persi ($GOT_CREATED < $N)"; FAIL=1; fi
if [ "$GOT_EXIT" -lt "$N" ]; then echo "FAIL: exit persi ($GOT_EXIT < $N)"; FAIL=1; fi
if [ "$FAIL" -eq 0 ]; then echo "LOSS_OK: zero eventi persi (created+exited)"; fi
[ "$FAIL" -eq 0 ] && echo "BENCH_PASS" || echo "BENCH_FAIL"
exit $FAIL
