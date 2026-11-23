#!/bin/sh
# Functional smoke test for the packaged ak CLI without Docker or systemd.
# Run on Linux/WSL: sh scripts/tests/ak_smoke.sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
AK="$ROOT/packaging/server/ak.sh"
HELPER="$ROOT/packaging/server/aegis/ui-port.sh"
TMP="$(mktemp -d)"
trap 'kill "${HOLDER_PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

BIN="$TMP/bin"
mkdir -p "$BIN" "$TMP/server" "$TMP/kraken"
cat > "$BIN/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then
    echo 0
else
    exec /usr/bin/id "$@"
fi
EOF
cat > "$BIN/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
    "is-active --quiet "*) exit 3 ;;
    "is-active "*) echo inactive; exit 3 ;;
    "is-enabled --quiet "*) exit 0 ;;
    "is-enabled "*) echo enabled; exit 0 ;;
    start*|stop*|restart*) printf '%s\n' "$*" >> "$AK_SMOKE_SYSTEMCTL"; exit 0 ;;
    *) exit 0 ;;
esac
EOF
cat > "$BIN/docker" <<'EOF'
#!/bin/sh
case "$*" in
    "compose version") echo "Docker Compose version v2.29.0" ;;
    "info --format "*) echo "27.0" ;;
    ps*) : ;;
    compose*) echo "fake compose: $*" ;;
    *) echo "fake docker: $*" ;;
esac
EOF
cat > "$BIN/dpkg-query" <<'EOF'
#!/bin/sh
echo 4.3.0
EOF
chmod 0755 "$BIN/id" "$BIN/systemctl" "$BIN/docker" "$BIN/dpkg-query"

ENV_FILE="$TMP/server.env"
cat > "$ENV_FILE" <<'EOF'
AEGIS_DOMAIN=aegis.local
ACME_EMAIL=internal
AEGIS_UI_PORT=3000
PUBLIC_BASE_URL=https://aegis.local
ALLOWED_ORIGINS=https://aegis.local,http://localhost:3000
EOF
chmod 0600 "$ENV_FILE"
KRAKEN_ENV_FILE="$TMP/kraken.env"
cat > "$KRAKEN_ENV_FILE" <<'EOF'
KRAKEN_PORT_EXTERNAL=8001
KRAKEN_PUBLIC_BASE_PATH=
EOF
chmod 0600 "$KRAKEN_ENV_FILE"
export PATH="$BIN:$PATH"
export AK_SERVER_DIR="$TMP/server"
export AK_KRAKEN_DIR="$TMP/kraken"
export AK_SERVER_ENV="$ENV_FILE"
export AK_KRAKEN_ENV="$KRAKEN_ENV_FILE"
export AK_UI_HELPER="$HELPER"
export AK_SMOKE_SYSTEMCTL="$TMP/systemctl.log"

# A real listener on 3000 exercises the start-time fallback. If the port is
# already occupied, the same path is exercised without starting our holder.
python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",3000)); s.listen(); time.sleep(20)' \
    >/dev/null 2>&1 &
HOLDER_PID=$!
sleep 0.3

sh "$AK" --help > "$TMP/help.out"
grep -q "ak - manage the installed Aegis and Kraken server stacks" "$TMP/help.out"
grep -q "ak help \[command\]" "$TMP/help.out"
sh "$AK" help logs > "$TMP/help-logs.out"
grep -q "Usage: ak logs" "$TMP/help-logs.out"
sh "$AK" help update > "$TMP/help-update.out"
grep -q "Usage: ak update" "$TMP/help-update.out"
if sh "$AK" logs --bogus > "$TMP/bad-option.out" 2>&1; then
    echo "invalid logs option unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
sh "$AK" logs --help > "$TMP/help-logs-option.out"
grep -q "Usage: ak logs" "$TMP/help-logs-option.out"

sh "$AK" status > "$TMP/status.out"
grep -q "aegis" "$TMP/status.out"
grep -q "kraken" "$TMP/status.out"
if sh "$AK" status does-not-exist > "$TMP/unknown.out" 2>&1; then
    echo "unknown component unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
grep -q "unknown component" "$TMP/unknown.out"

sh "$AK" url > "$TMP/url-before.out"
grep -q "https://aegis.local/" "$TMP/url-before.out"

sh "$AK" start aegis > "$TMP/start.out"
grep -q "switched to" "$TMP/start.out"

# --wait blocks on the unit and then polls Compose; the fake docker answers with
# a running, healthy container so the loop must terminate before the timeout.
sh "$AK" start aegis --wait --timeout 5 > "$TMP/start-wait.out"
grep -q "Ready aegis" "$TMP/start-wait.out"
if sh "$AK" start aegis --timeout nope > "$TMP/start-bad-timeout.out" 2>&1; then
    echo "non-numeric start timeout unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
if sh "$AK" start aegis --bogus > "$TMP/start-bad-option.out" 2>&1; then
    echo "unknown start option unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
sh "$AK" url aegis > "$TMP/url-after.out"
grep -q "localhost:3001" "$TMP/url-after.out"

# The boot helper must also switch a stale 3000 when no Aegis frontend owns it.
sed -i 's/^AEGIS_UI_PORT=.*/AEGIS_UI_PORT=3000/' "$ENV_FILE"
sh "$ROOT/packaging/server/aegis/ensure-ui-port.sh" > "$TMP/ensure.out" 2>&1
grep -q "switched to 3001" "$TMP/ensure.out"

sh "$AK" ps aegis > "$TMP/ps.out"
grep -q "fake compose" "$TMP/ps.out"
sh "$AK" logs aegis --tail 5 > "$TMP/logs.out"
grep -q "fake compose" "$TMP/logs.out"

sh "$AK" configure --domain soc.example.com --email ops@example.com > "$TMP/configure.out"
sh "$AK" url aegis > "$TMP/url-configured.out"
grep -q "https://soc.example.com/" "$TMP/url-configured.out"
if sh "$AK" configure --domain 'bad..host' --email ops@example.com > "$TMP/bad-domain.out" 2>&1; then
    echo "invalid domain unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
if sh "$AK" configure --domain public.example.com --email internal > "$TMP/bad-email.out" 2>&1; then
    echo "public domain without ACME email unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
if sh "$AK" configure --domain soc.example.com --email ops@example.com --public-url https://other.example.com > "$TMP/bad-public.out" 2>&1; then
    echo "inconsistent public URL unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
if sh "$AK" update --version 4.2 --check > "$TMP/bad-version.out" 2>&1; then
    echo "invalid update version unexpectedly succeeded" >&2
    exit 1
else
    [ "$?" -eq 2 ]
fi
sh "$AK" update --version 4.3.0 --check > "$TMP/update-check.out"
grep -q "Installed: both 4.3.0" "$TMP/update-check.out"
grep -q "AEGIS_DOMAIN=soc.example.com" "$ENV_FILE"
grep -q "ALLOWED_ORIGINS=.*http://localhost:3001" "$ENV_FILE"

sh "$AK" stop aegis > "$TMP/stop.out"
grep -q "stop aegis.service" "$AK_SMOKE_SYSTEMCTL"

sh "$AK" doctor > "$TMP/doctor.out"
grep -q "OK    systemd" "$TMP/doctor.out"
grep -q "OK    aegis env" "$TMP/doctor.out"
grep -q "Resources:" "$TMP/doctor.out"
grep -q "host memory" "$TMP/doctor.out"

printf 'ak smoke PASS\n'
