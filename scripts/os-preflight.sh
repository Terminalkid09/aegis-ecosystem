#!/bin/sh
# Preflight validazione OS per Aegis (Ubuntu / Debian / RHEL).
# Controlli read-only pre-installazione. Exit 0 = pass, 1 = fail. Non modifica il sistema.
# Uso: sh scripts/os-preflight.sh
FAILED=0
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1 -- $2"; FAILED=$((FAILED + 1)); }

if [ -f /etc/os-release ]; then . /etc/os-release; else ID=unknown; VERSION_ID=0; fi
case "$ID" in
  ubuntu) [ "${VERSION_ID%%.*}" -ge 22 ] 2>/dev/null && pass "OS Ubuntu $VERSION_ID" || fail "OS Ubuntu $VERSION_ID" "richiesto Ubuntu 22.04+" ;;
  debian) [ "${VERSION_ID%%.*}" -ge 12 ] 2>/dev/null && pass "OS Debian $VERSION_ID" || fail "OS Debian $VERSION_ID" "richiesto Debian 12+" ;;
  rhel|rocky|almalinux) [ "${VERSION_ID%%.*}" -ge 9 ] 2>/dev/null && pass "OS $ID $VERSION_ID" || fail "OS $ID $VERSION_ID" "richiesto RHEL 9+" ;;
  *) fail "OS $ID $VERSION_ID" "distro supportate: Ubuntu 22.04+, Debian 12+, RHEL 9+" ;;
esac

command -v docker >/dev/null 2>&1 && pass "Docker disponibile" || fail "Docker disponibile" "installare Docker 24+"
docker info 2>/dev/null | grep -q "Server Version" && pass "Docker daemon raggiungibile" || fail "Docker daemon" "avviare dockerd / utente nel gruppo docker"

if command -v python3 >/dev/null 2>&1 && python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
  pass "Python 3.10+ disponibile"
else
  fail "Python 3.10+" "installare python3.10+"
fi

BUSY=""
for p in 5444 6388 8000 3000; do
  if (command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$p ") || \
     (command -v netstat >/dev/null 2>&1 && netstat -ltn 2>/dev/null | grep -q ":$p "); then
    BUSY="$BUSY $p"
  fi
done
[ -z "$BUSY" ] && pass "Porte 5444/6388/8000/3000 libere" || fail "Porte occupate:$BUSY" "porte occupate da altri servizi"

FREE_KB=$(df -k / | awk 'NR==2 {print $4}')
[ "${FREE_KB:-0}" -gt 20971520 ] && pass "Disco libero >= 20 GB" || fail "Disco libero" "liberare spazio su disco"

MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
[ "${MEM_KB:-0}" -gt 4000000 ] && pass "RAM >= 4 GB" || fail "RAM" "host sotto i requisiti minimi pilot"

if [ "$FAILED" -gt 0 ]; then echo "PREFLIGHT: $FAILED check falliti"; exit 1; fi
echo "PREFLIGHT: tutti i check passati"
exit 0
