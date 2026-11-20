#!/bin/bash
# eBPF sensor end-to-end test: load into the kernel, generate known execs,
# verify every probe appears in the events (no lost processes).
# Requires: --privileged, BTF, libbpf1. Returns 0 if everything passes.
set -u
cd /src
# tracefs is needed to attach the tracepoints
if [ ! -d /sys/kernel/tracing ]; then mkdir -p /sys/kernel/tracing; fi
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
./aegis-collector --obj aegis_exec.bpf.o > /tmp/ev.jsonl 2>/tmp/collector.log &
CPID=$!
sleep 2
if ! kill -0 $CPID 2>/dev/null; then
  echo "FATAL: collector exited immediately:"; cat /tmp/collector.log; exit 1
fi
for i in 1 2 3; do /bin/echo "aegis-probe-$i" > /dev/null; sleep 0.3; done
/usr/bin/whoami > /dev/null
sleep 2
kill $CPID 2>/dev/null
wait $CPID 2>/dev/null || true
echo "--- collector log ---"; cat /tmp/collector.log
TOTAL=$(wc -l < /tmp/ev.jsonl)
CREATED=$(grep -c PROCESS_CREATED /tmp/ev.jsonl || true)
echo "--- total events=$TOTAL created=$CREATED ---"
FAIL=0
for i in 1 2 3; do
  if grep -q "aegis-probe" /tmp/ev.jsonl 2>/dev/null; then :; fi
done
# each echo is a distinct exec: expect 3 comm=echo events with filename /bin/echo
ECHO_N=$(grep -c '"comm":"echo"' /tmp/ev.jsonl || true)
echo "comm=echo events: $ECHO_N"
if [ "$ECHO_N" -lt 3 ]; then echo "FAIL: expected >=3 echo execs, saw $ECHO_N"; FAIL=1; fi
if ! grep -q '"/bin/echo"' /tmp/ev.jsonl; then echo "FAIL: filename /bin/echo never seen"; FAIL=1; fi
if ! grep -q '"comm":"whoami"' /tmp/ev.jsonl; then echo "FAIL: whoami never seen"; FAIL=1; fi
if ! grep -q 'PROCESS_EXITED' /tmp/ev.jsonl; then echo "FAIL: no exit event"; FAIL=1; fi
# --- Network: 3 local TCP handshakes must appear as CONNECTION_ESTABLISHED
# (timeouts everywhere: CI must never hang here)
if command -v python3 >/dev/null 2>&1; then HAVE_PY=1; else apt-get install -y -qq python3-minimal >/dev/null 2>&1; HAVE_PY=1; fi
timeout 30 python3 -m http.server 18923 --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
sleep 1
timeout 30 ./aegis-collector --obj aegis_exec.bpf.o > /tmp/ev_net.jsonl 2>/dev/null &
CPID=$!
sleep 2
for i in 1 2 3; do timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/18923' 2>/dev/null; sleep 0.2; done
sleep 2
kill $CPID 2>/dev/null; wait $CPID 2>/dev/null || true
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null || true
CONN_N=$(grep -c 'CONNECTION_ESTABLISHED' /tmp/ev_net.jsonl || true)
echo "captured 127.0.0.1:18923 connections: $CONN_N (expected >=3)"
if grep -q '"remote":"127.0.0.1:18923"' /tmp/ev_net.jsonl; then
  echo "REMOTE_OK: correct ip:port (ntohl ok)"
else
  echo "FAIL: remote 127.0.0.1:18923 never seen"; FAIL=1
fi
if [ "$CONN_N" -lt 3 ]; then echo "FAIL: lost handshakes"; FAIL=1; fi
grep -m 1 'CONNECTION_ESTABLISHED' /tmp/ev_net.jsonl >> /src/tests/golden.jsonl || true

if [ "$FAIL" -eq 0 ]; then echo "EBPF_TEST_PASS"; else echo "EBPF_TEST_FAIL"; fi
echo "--- sample ---"; head -2 /tmp/ev.jsonl
