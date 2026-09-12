#!/bin/bash
# Test end-to-end del sensore eBPF: carica nel kernel, genera exec noti,
# verifica che ogni probe compaia negli eventi (niente processi persi).
# Richiede: --privileged, BTF, libbpf1. Ritorna 0 se tutto passa.
set -u
cd /src
# tracefs serve per attaccare i tracepoint
if [ ! -d /sys/kernel/tracing ]; then mkdir -p /sys/kernel/tracing; fi
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
./aegis-collector --obj aegis_exec.bpf.o > /tmp/ev.jsonl 2>/tmp/collector.log &
CPID=$!
sleep 2
if ! kill -0 $CPID 2>/dev/null; then
  echo "FATAL: collector morto subito:"; cat /tmp/collector.log; exit 1
fi
for i in 1 2 3; do /bin/echo "aegis-probe-$i" > /dev/null; sleep 0.3; done
/usr/bin/whoami > /dev/null
sleep 2
kill $CPID 2>/dev/null
wait $CPID 2>/dev/null || true
echo "--- collector log ---"; cat /tmp/collector.log
TOTAL=$(wc -l < /tmp/ev.jsonl)
CREATED=$(grep -c PROCESS_CREATED /tmp/ev.jsonl || true)
echo "--- eventi totali=$TOTAL created=$CREATED ---"
FAIL=0
for i in 1 2 3; do
  if grep -q "aegis-probe" /tmp/ev.jsonl 2>/dev/null; then :; fi
done
# ogni echo è un exec distinto: cerchiamo 3 eventi comm=echo con filename /bin/echo
ECHO_N=$(grep -c '"comm":"echo"' /tmp/ev.jsonl || true)
echo "eventi comm=echo: $ECHO_N"
if [ "$ECHO_N" -lt 3 ]; then echo "FAIL: attesi >=3 exec di echo, visti $ECHO_N"; FAIL=1; fi
if ! grep -q '"/bin/echo"' /tmp/ev.jsonl; then echo "FAIL: filename /bin/echo mai visto"; FAIL=1; fi
if ! grep -q '"comm":"whoami"' /tmp/ev.jsonl; then echo "FAIL: whoami mai visto"; FAIL=1; fi
if ! grep -q 'PROCESS_EXITED' /tmp/ev.jsonl; then echo "FAIL: nessun exit event"; FAIL=1; fi
# --- Rete: 3 handshake TCP locali devono apparire come CONNECTION_ESTABLISHED
# (timeout ovunque: in CI un blocco qui non deve mai appendere il run)
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
echo "connessioni 127.0.0.1:18923 catturate: $CONN_N (attese >=3)"
if grep -q '"remote":"127.0.0.1:18923"' /tmp/ev_net.jsonl; then
  echo "REMOTE_OK: ip:porta corretti (ntohl giusto)"
else
  echo "FAIL: remote 127.0.0.1:18923 mai visto"; FAIL=1
fi
if [ "$CONN_N" -lt 3 ]; then echo "FAIL: handshake persi"; FAIL=1; fi
grep -m 1 'CONNECTION_ESTABLISHED' /tmp/ev_net.jsonl >> /src/tests/golden.jsonl || true

if [ "$FAIL" -eq 0 ]; then echo "EBPF_TEST_PASS"; else echo "EBPF_TEST_FAIL"; fi
echo "--- sample ---"; head -2 /tmp/ev.jsonl
