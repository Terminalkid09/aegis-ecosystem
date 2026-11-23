#!/usr/bin/env bash
# Build an OpenWrt .ipk for the static Go agent. The package uses procd, keeps
# the enrollment token outside the package, and does not start until configured.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-4.3.0}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
AGENT_BIN="${AGENT_BIN:-$ROOT/.tmp/packaging/aegis-agent-linux}"

if ! command -v ar >/dev/null 2>&1; then
    echo "ar not found. Install binutils on the packaging host." >&2
    exit 2
fi
if [ ! -f "$AGENT_BIN" ]; then
    mkdir -p "$(dirname "$AGENT_BIN")"
    (cd "$ROOT/aegis-agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath -ldflags "-s -w -X main.buildVersion=$VERSION" \
        -o "$AGENT_BIN" ./cmd/aegis-agent)
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/data/usr/sbin" "$STAGE/data/etc/init.d" \
    "$STAGE/data/etc/config" "$STAGE/data/var/lib/aegis-agent" "$STAGE/control"
install -m 0755 "$AGENT_BIN" "$STAGE/data/usr/sbin/aegis-agent"

cat > "$STAGE/data/etc/config/aegis-agent" <<'EOF'
config agent 'main'
    option enabled '1'
    option brain_url 'https://aegis.local'
    option mode 'full'
EOF

cat > "$STAGE/data/etc/init.d/aegis-agent" <<'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
    config_load aegis-agent
    local enabled brain_url mode
    config_get enabled main enabled '1'
    config_get brain_url main brain_url 'https://aegis.local'
    config_get mode main mode 'full'
    [ "$enabled" = "1" ] || return 0
    procd_open_instance
    procd_set_param command /usr/sbin/aegis-agent --profile unified --home /var/lib/aegis-agent
    procd_set_param env AEGIS_AGENT_PROFILE=unified AEGIS_AGENT_MODE="$mode" \
        AEGIS_BRAIN_URL="$brain_url" AEGIS_IDENTITY_DIR=/var/lib/aegis-agent \
        AEGIS_ENROLL_TOKEN_FILE=/etc/aegis-agent/enroll.token
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger aegis-agent
}
EOF
chmod 0755 "$STAGE/data/etc/init.d/aegis-agent"
install -d -m 0750 "$STAGE/data/etc/aegis-agent"
install -m 0600 /dev/null "$STAGE/data/etc/aegis-agent/.keep"
install -m 0644 "$ROOT/aegis-agent/packaging/linux/etc/aegis-agent/aegis-agent.env.example" \
    "$STAGE/data/etc/aegis-agent/aegis-agent.env.example"

SIZE="$(du -sk "$STAGE/data" | cut -f1)"
cat > "$STAGE/control/control" <<EOF
Package: aegis-agent
Version: ${VERSION}-1
Depends: ca-bundle
Source: https://github.com/Terminalkid09/aegis-ecosystem
Section: admin
Priority: optional
Maintainer: Aegis <ops@aegis.local>
Architecture: x86_64
Installed-Size: ${SIZE}
Description: Aegis unified endpoint and sensor agent
 One binary with explicit full, sensor and endpoint modes. Enrollment is
 provisioned by the operator or MDM; the package does not contain a token.
EOF

cat > "$STAGE/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] || /etc/init.d/aegis-agent enable
exit 0
EOF
cat > "$STAGE/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] || /etc/init.d/aegis-agent stop || true
exit 0
EOF
chmod 0755 "$STAGE/control/postinst" "$STAGE/control/prerm"

mkdir -p "$OUT_DIR"
(cd "$STAGE/control" && tar -czf "$STAGE/control.tar.gz" .)
(cd "$STAGE/data" && tar -czf "$STAGE/data.tar.gz" .)
printf '2.0\n' > "$STAGE/debian-binary"
IPK="$OUT_DIR/aegis-agent_${VERSION}_x86_64.ipk"
(cd "$STAGE" && ar r "$IPK" debian-binary control.tar.gz data.tar.gz >/dev/null)
ar t "$IPK" > "$STAGE/ipk.members"
grep -qx debian-binary "$STAGE/ipk.members"
grep -qx control.tar.gz "$STAGE/ipk.members"
grep -qx data.tar.gz "$STAGE/ipk.members"
tar -tzf "$STAGE/control.tar.gz" > "$STAGE/control.members"
tar -tzf "$STAGE/data.tar.gz" > "$STAGE/data.members"
grep -qx ./control "$STAGE/control.members"
grep -qx ./usr/sbin/aegis-agent "$STAGE/data.members"
(cd "$OUT_DIR" && sha256sum "$(basename "$IPK")" > "$(basename "$IPK").sha256")
echo "OPKG: $IPK"
echo "SHA256: $(cut -d' ' -f1 "$IPK.sha256")"
