#!/usr/bin/env bash
# Build a .deb for the unified agent and attach a detached GPG signature.
# Default is TEST signing with an ephemeral key; production must pass GPG_KEY_ID.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-4.3.0}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
AGENT_BIN="${AGENT_BIN:-$ROOT/.tmp/packaging/aegis-agent-linux}"
SKIP_SIGN="${SKIP_SIGN:-0}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb not found. On Windows run this script in debian:bookworm-slim:" >&2
    echo "  docker run --rm -v \"$ROOT:/src\" -v \"$OUT_DIR:/out\" -e VERSION=$VERSION \\" >&2
    echo "    debian:bookworm-slim bash -lc 'apt-get update -qq && apt-get install -y -qq dpkg-dev gnupg >/dev/null && /src/scripts/build-deb.sh'" >&2
    exit 2
fi

if [ ! -f "$AGENT_BIN" ]; then
    mkdir -p "$(dirname "$AGENT_BIN")"
    (cd "$ROOT/aegis-agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath -ldflags "-s -w -X main.buildVersion=$VERSION" \
        -o "$AGENT_BIN" ./cmd/aegis-agent)
fi

STAGE="$(mktemp -d)"
TMP_GPG=""
cleanup() {
    rm -rf "$STAGE"
    if [ -n "$TMP_GPG" ]; then rm -rf "$TMP_GPG"; fi
}
trap cleanup EXIT

mkdir -p "$STAGE/DEBIAN" \
    "$STAGE/usr/local/bin" \
    "$STAGE/usr/local/lib/aegis-agent" \
    "$STAGE/lib/systemd/system" \
    "$STAGE/etc/aegis-agent"
install -m 0755 "$AGENT_BIN" "$STAGE/usr/local/bin/aegis-agent"

# Include the kernel helpers when they are present in the tree. The agent
# degrades explicitly to auditd/no-eBPF if they are absent; the package does
# not pretend they are installed when they are not.
EBPF_COLLECTOR="${EBPF_COLLECTOR:-$ROOT/aegis-ebpf/aegis-collector}"
EBPF_OBJ="${EBPF_OBJ:-$ROOT/aegis-ebpf/aegis_exec.bpf.o}"
if [ -f "$EBPF_COLLECTOR" ]; then
    install -m 0755 "$EBPF_COLLECTOR" "$STAGE/usr/local/lib/aegis-agent/aegis-collector"
fi
if [ -f "$EBPF_OBJ" ]; then
    install -m 0644 "$EBPF_OBJ" "$STAGE/usr/local/lib/aegis-agent/aegis_exec.bpf.o"
fi
install -m 0644 "$ROOT/aegis-agent/packaging/linux/lib/systemd/system/aegis-agent.service" \
    "$STAGE/lib/systemd/system/aegis-agent.service"
install -m 0644 "$ROOT/aegis-agent/packaging/linux/etc/aegis-agent/aegis-agent.env.example" \
    "$STAGE/etc/aegis-agent/aegis-agent.env.example"
install -m 0755 "$ROOT/aegis-agent/packaging/linux/DEBIAN/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/aegis-agent/packaging/linux/DEBIAN/prerm" "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/aegis-agent/packaging/linux/DEBIAN/postrm" "$STAGE/DEBIAN/postrm"

SIZE="$(du -sk "$STAGE" | cut -f1)"
sed -e "s/__VERSION__/$VERSION/" -e "s/__SIZE__/$SIZE/" \
    "$ROOT/aegis-agent/packaging/linux/DEBIAN/control" > "$STAGE/DEBIAN/control"

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/aegis-agent_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null
dpkg-deb --info "$DEB" >/dev/null
dpkg-deb --contents "$DEB" >/dev/null

if [ "$SKIP_SIGN" != "1" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "gpg not found: cannot produce the test signature" >&2
        exit 2
    fi
    if [ -z "$GPG_KEY_ID" ]; then
        TMP_GPG="$(mktemp -d)"
        export GNUPGHOME="$TMP_GPG"
        chmod 700 "$GNUPGHOME"
        gpg --batch --passphrase '' --quick-gen-key \
            "Aegis Test Packaging <packaging@aegis.local>" rsa2048 sign 1d >/dev/null 2>&1
        GPG_KEY_ID="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/{print $5; exit}')"
        echo "test signing key: $GPG_KEY_ID (ephemeral, not trusted)"
    fi
    gpg --batch --yes --armor --detach-sign --local-user "$GPG_KEY_ID" \
        --output "$DEB.asc" "$DEB"
    gpg --batch --verify "$DEB.asc" "$DEB" >/dev/null
    echo "GPG signature verified: $DEB.asc"
fi

(cd "$OUT_DIR" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256")
echo "DEB: $DEB"
echo "SHA256: $(cut -d' ' -f1 "$DEB.sha256")"
