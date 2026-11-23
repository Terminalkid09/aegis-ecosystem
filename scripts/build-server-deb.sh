#!/usr/bin/env bash
# Build the complete server packages:
#   aegis       - Brain, Link, dashboard, PostgreSQL, Redis, Caddy, backup
#   kraken      - app, sensors, broker, RDP, private PostgreSQL/Redis
#   aegis-suite - metapackage that installs both, plus a one-file bundle
#
# The packages install source and Compose files, not multi-GB prebuilt images.
# The first systemctl start builds the images. Signing defaults to a persistent
# self-signed pilot GPG key; production signing requires GPG_KEY_ID and a key in
# the operator's GNUPGHOME. Self-signed is not a publicly trusted identity.
# The unit uses Wants=docker.service so Docker Desktop WSL can also start it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-4.3.0}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
SIGNING_MODE="${SIGNING_MODE:-self-signed}"
GPG_KEY_ID="${GPG_KEY_ID:-}"
GPG_HOME="${GPG_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/aegis-gpg}"
STAGE_ROOT="$(mktemp -d)"
TMP_GPG=""
trap 'rm -rf "$STAGE_ROOT"; if [ -n "$TMP_GPG" ]; then rm -rf "$TMP_GPG"; fi' EXIT

case "$SIGNING_MODE" in
    self-signed|test|production|unsigned) ;;
    *) echo "SIGNING_MODE must be self-signed, test, production or unsigned" >&2; exit 2 ;;
esac

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb not found. Run this on Debian/Ubuntu or in debian:bookworm-slim." >&2
    exit 2
fi

copy_tree() {
    local src="$1" dst="$2"
    shift 2
    mkdir -p "$dst"
    tar -C "$src" "$@" -cf - . | tar -C "$dst" -xf -
}

normalize_text() {
    local file
    for file in "$@"; do
        [ -f "$file" ] && sed -i 's/\r$//' "$file"
    done
}

sign_deb() {
    local deb="$1" hash key_home
    hash="$(sha256sum "$deb" | awk '{print $1}')"

    if [ "$SIGNING_MODE" = "unsigned" ]; then
        printf '{"schema":"aegis-package-signing-v1","package":"%s","mode":"unsigned","sha256":"%s"}\n' \
            "$(basename "$deb")" "$hash" > "$deb.signing.json"
        return 0
    fi

    if ! command -v gpg >/dev/null 2>&1; then
        echo "gpg not found: cannot sign $deb" >&2
        exit 2
    fi

    if [ "$SIGNING_MODE" = "production" ]; then
        if [ -z "$GPG_KEY_ID" ]; then
            echo "production signing requires GPG_KEY_ID" >&2
            exit 2
        fi
        if ! gpg --batch --list-secret-keys "$GPG_KEY_ID" >/dev/null 2>&1; then
            echo "GPG_KEY_ID has no secret key in the current GNUPGHOME: $GPG_KEY_ID" >&2
            exit 2
        fi
    elif [ "$SIGNING_MODE" = "self-signed" ]; then
        export GNUPGHOME="${GNUPGHOME:-$GPG_HOME}"
        mkdir -p "$GNUPGHOME"
        chmod 700 "$GNUPGHOME"
        if [ -z "$GPG_KEY_ID" ]; then
            GPG_KEY_ID="$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec:/{print $5; exit}')"
        fi
        if [ -z "$GPG_KEY_ID" ]; then
            gpg --batch --passphrase '' --quick-gen-key \
                "Aegis Pilot Self-Signed <pilot@aegis.local>" rsa3072 sign 0 >/dev/null 2>&1
            GPG_KEY_ID="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/{print $5; exit}')"
        fi
        gpg --armor --export "$GPG_KEY_ID" > "$OUT_DIR/aegis-pilot-signing-key.asc"
    else
        TMP_GPG="$(mktemp -d)"
        export GNUPGHOME="$TMP_GPG"
        chmod 700 "$GNUPGHOME"
        gpg --batch --passphrase '' --quick-gen-key \
            "Aegis Test Packaging <packaging@aegis.local>" rsa2048 sign 1d >/dev/null 2>&1
        GPG_KEY_ID="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/{print $5; exit}')"
        gpg --armor --export "$GPG_KEY_ID" > "$OUT_DIR/aegis-test-signing-key.asc"
    fi

    gpg --batch --yes --armor --detach-sign --local-user "$GPG_KEY_ID" \
        --output "$deb.asc" "$deb"
    gpg --batch --verify "$deb.asc" "$deb" >/dev/null
    printf '{"schema":"aegis-package-signing-v1","package":"%s","mode":"%s","sha256":"%s","signer":"%s"}\n' \
        "$(basename "$deb")" "$SIGNING_MODE" "$hash" "$GPG_KEY_ID" > "$deb.signing.json"
    echo "signed $(basename "$deb") ($SIGNING_MODE)"
}

build_aegis() {
    local stage="$STAGE_ROOT/aegis"
    local app="$stage/opt/aegis/server"
    local deb="$OUT_DIR/aegis_${VERSION}_amd64.deb"
    local doc="$stage/usr/share/doc/aegis"

    install -d -m 0755 "$stage/DEBIAN" "$doc" "$app"
    install -m 0644 "$ROOT/docker-compose.yml" "$app/docker-compose.yml"
    install -m 0644 "$ROOT/docker-compose.prod.yml" "$app/docker-compose.prod.yml"
    install -m 0644 "$ROOT/docker-compose.mtls.yml" "$app/docker-compose.mtls.yml"
    install -m 0644 "$ROOT/docker-compose.ha.yml" "$app/docker-compose.ha.yml"
    install -m 0644 "$ROOT/Caddyfile" "$app/Caddyfile"
    install -m 0644 "$ROOT/Caddyfile.mtls" "$app/Caddyfile.mtls"
    install -m 0644 "$ROOT/.env.example" "$app/.env.example"
    install -m 0644 "$ROOT/packaging/server/README.md" "$doc/README.md"
    install -m 0644 "$ROOT/docs/AK_CLI.md" "$doc/AK_CLI.md"

    copy_tree "$ROOT/aegis-brain" "$app/aegis-brain" \
        --exclude=.env --exclude=.env.* --exclude=.venv --exclude=__pycache__ \
        --exclude=.pytest_cache --exclude=.pytest-temp --exclude=tests \
        --exclude=.ruff_cache --exclude=.mypy_cache --exclude=.coverage \
        --exclude=htmlcov --exclude=.git --exclude=.github
    copy_tree "$ROOT/aegis-link" "$app/aegis-link" \
        --exclude=target --exclude=link-test.log --exclude=src/test \
        --exclude=.git --exclude=.github
    copy_tree "$ROOT/frontend" "$app/frontend" \
        --exclude=node_modules --exclude=dist --exclude=test-results \
        --exclude=e2e --exclude=playwright.config.ts --exclude=.env --exclude=.env.* \
        --exclude=.vite --exclude=.cache --exclude=coverage --exclude=.git --exclude=.github
    install -d -m 0755 "$app/scripts"
    install -m 0755 "$ROOT/scripts/backup-db.sh" "$app/scripts/backup-db.sh"
    install -m 0755 "$ROOT/scripts/backup-pki.sh" "$app/scripts/backup-pki.sh"
    install -d -m 0750 "$app/secrets"

    find "$app" -type d -exec chmod 0755 {} +
    find "$app" -type f -exec chmod 0644 {} +
    chmod 0755 "$app/scripts/backup-db.sh" "$app/scripts/backup-pki.sh"

    install -m 0644 "$ROOT/LICENSE" "$doc/LICENSE"
    install -m 0644 "$ROOT/NOTICE" "$doc/NOTICE"
    install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$doc/THIRD_PARTY_NOTICES.md"

    install -d -m 0755 "$stage/usr/local/lib/aegis" "$stage/etc/systemd/system"
    install -m 0644 "$ROOT/packaging/server/aegis/aegis.service" \
        "$stage/etc/systemd/system/aegis.service"
    install -m 0755 "$ROOT/packaging/server/aegis/build-server.sh" \
        "$stage/usr/local/lib/aegis/build-server.sh"
    install -m 0755 "$ROOT/packaging/server/aegis/server-env.sh" \
        "$stage/usr/local/lib/aegis/server-env.sh"
    install -m 0644 "$ROOT/packaging/server/aegis/ui-port.sh" \
        "$stage/usr/local/lib/aegis/ui-port.sh"
    install -m 0755 "$ROOT/packaging/server/aegis/ensure-ui-port.sh" \
        "$stage/usr/local/lib/aegis/ensure-ui-port.sh"
    sed -e "s/__VERSION__/$VERSION/g" "$ROOT/packaging/server/ak.sh" \
        > "$stage/usr/local/lib/aegis/ak-aegis"
    chmod 0755 "$stage/usr/local/lib/aegis/ak-aegis"
    install -m 0755 "$ROOT/packaging/server/aegis/config" "$stage/DEBIAN/config"
    install -m 0644 "$ROOT/packaging/server/aegis/templates" "$stage/DEBIAN/templates"
    install -m 0755 "$ROOT/packaging/server/aegis/postinst" "$stage/DEBIAN/postinst"
    install -m 0755 "$ROOT/packaging/server/aegis/prerm" "$stage/DEBIAN/prerm"
    install -m 0755 "$ROOT/packaging/server/aegis/postrm" "$stage/DEBIAN/postrm"
    normalize_text "$stage/DEBIAN/config" "$stage/DEBIAN/templates" \
        "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm" \
        "$stage/etc/systemd/system/aegis.service" \
        "$stage/usr/local/lib/aegis/build-server.sh" \
        "$stage/usr/local/lib/aegis/server-env.sh" \
        "$stage/usr/local/lib/aegis/ui-port.sh" \
        "$stage/usr/local/lib/aegis/ensure-ui-port.sh" \
        "$stage/usr/local/lib/aegis/ak-aegis"

    local size
    size="$(du -sk "$stage" | cut -f1)"
    sed -e "s/__VERSION__/$VERSION/" -e "s/__SIZE__/$size/" \
        "$ROOT/packaging/server/aegis/control" > "$stage/DEBIAN/control"

    mkdir -p "$OUT_DIR"
    dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null
    dpkg-deb --info "$deb" >/dev/null
    sign_deb "$deb"
    (cd "$OUT_DIR" && sha256sum "$(basename "$deb")" > "$(basename "$deb").sha256")
    echo "aegis: $deb"
}

build_kraken() {
    local stage="$STAGE_ROOT/kraken"
    local app="$stage/opt/aegis/kraken"
    local deb="$OUT_DIR/kraken_${VERSION}_amd64.deb"
    local doc="$stage/usr/share/doc/kraken"

    install -d -m 0755 "$stage/DEBIAN" "$doc" "$app"
    install -m 0644 "$ROOT/packaging/server/kraken/docker-compose.yml" \
        "$app/docker-compose.yml"
    install -m 0644 "$ROOT/packaging/server/README.md" "$doc/README.md"
    install -m 0644 "$ROOT/docs/AK_CLI.md" "$doc/AK_CLI.md"
    copy_tree "$ROOT/services/kraken" "$app/services/kraken" \
        --exclude=.env --exclude=.env.* --exclude=.coverage --exclude=htmlcov \
        --exclude=.pytest_cache --exclude=.ruff_cache --exclude=__pycache__ \
        --exclude=tests --exclude=secrets --exclude=data --exclude=monitoring \
        --exclude=nginx --exclude=.git --exclude=.github

    find "$app" -type d -exec chmod 0755 {} +
    find "$app" -type f -exec chmod 0644 {} +
    if [ -f "$app/services/kraken/sandbox-init.sh" ]; then
        chmod 0755 "$app/services/kraken/sandbox-init.sh"
    fi
    if [ -d "$app/services/kraken/rdp" ]; then
        chmod 0755 "$app/services/kraken/rdp/"*.sh 2>/dev/null || true
    fi

    install -m 0644 "$ROOT/LICENSE" "$doc/LICENSE-AGPL"
    install -m 0644 "$ROOT/NOTICE" "$doc/NOTICE"
    if [ -f "$ROOT/services/kraken/LICENSE" ]; then
        install -m 0644 "$ROOT/services/kraken/LICENSE" "$doc/LICENSE-KRAKEN"
    fi

    install -d -m 0755 "$stage/usr/local/lib/aegis" "$stage/etc/systemd/system"
    install -m 0644 "$ROOT/packaging/server/kraken/kraken.service" \
        "$stage/etc/systemd/system/kraken.service"
    install -m 0755 "$ROOT/packaging/server/kraken/build-kraken.sh" \
        "$stage/usr/local/lib/aegis/build-kraken.sh"
    install -m 0755 "$ROOT/packaging/server/kraken/kraken-up.sh" \
        "$stage/usr/local/lib/aegis/kraken-up.sh"
    install -m 0755 "$ROOT/packaging/server/kraken/kraken-down.sh" \
        "$stage/usr/local/lib/aegis/kraken-down.sh"
    install -m 0755 "$ROOT/packaging/server/kraken/kraken-env.sh" \
        "$stage/usr/local/lib/aegis/kraken-env.sh"
    sed -e "s/__VERSION__/$VERSION/g" "$ROOT/packaging/server/ak.sh" \
        > "$stage/usr/local/lib/aegis/ak-kraken"
    chmod 0755 "$stage/usr/local/lib/aegis/ak-kraken"
    install -m 0755 "$ROOT/packaging/server/kraken/postinst" "$stage/DEBIAN/postinst"
    install -m 0755 "$ROOT/packaging/server/kraken/prerm" "$stage/DEBIAN/prerm"
    install -m 0755 "$ROOT/packaging/server/kraken/postrm" "$stage/DEBIAN/postrm"
    normalize_text "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" \
        "$stage/DEBIAN/postrm" "$stage/etc/systemd/system/kraken.service" \
        "$stage/usr/local/lib/aegis/build-kraken.sh" \
        "$stage/usr/local/lib/aegis/kraken-up.sh" \
        "$stage/usr/local/lib/aegis/kraken-down.sh" \
        "$stage/usr/local/lib/aegis/kraken-env.sh" \
        "$stage/usr/local/lib/aegis/ak-kraken"

    local size
    size="$(du -sk "$stage" | cut -f1)"
    sed -e "s/__VERSION__/$VERSION/" -e "s/__SIZE__/$size/" \
        "$ROOT/packaging/server/kraken/control" > "$stage/DEBIAN/control"

    mkdir -p "$OUT_DIR"
    dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null
    dpkg-deb --info "$deb" >/dev/null
    sign_deb "$deb"
    (cd "$OUT_DIR" && sha256sum "$(basename "$deb")" > "$(basename "$deb").sha256")
    echo "kraken: $deb"
}

build_suite() {
    local stage="$STAGE_ROOT/aegis-suite"
    local deb="$OUT_DIR/aegis-suite_${VERSION}_all.deb"
    local doc="$stage/usr/share/doc/aegis-suite"

    install -d -m 0755 "$stage/DEBIAN" "$doc" "$stage/usr/local/lib/aegis"
    install -m 0644 "$ROOT/packaging/server/README.md" "$doc/README.md"
    install -m 0644 "$ROOT/docs/AK_CLI.md" "$doc/AK_CLI.md" 2>/dev/null || true
    install -m 0755 "$ROOT/packaging/server/aegis-suite/postinst" "$stage/DEBIAN/postinst"
    install -m 0755 "$ROOT/packaging/server/aegis-suite/wire.sh" \
        "$stage/usr/local/lib/aegis/suite-wire.sh"
    normalize_text "$stage/DEBIAN/postinst" "$stage/usr/local/lib/aegis/suite-wire.sh"
    local size
    size="$(du -sk "$stage" | cut -f1)"
    sed -e "s/__VERSION__/$VERSION/g" -e "s/__SIZE__/$size/g" \
        "$ROOT/packaging/server/aegis-suite/control" > "$stage/DEBIAN/control"

    dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null
    dpkg-deb --info "$deb" >/dev/null
    sign_deb "$deb"
    (cd "$OUT_DIR" && sha256sum "$(basename "$deb")" > "$(basename "$deb").sha256")
    echo "aegis-suite: $deb"

    # One download for an offline/pilot host. The agent is included for the
    # operator but is not installed by install.sh: it belongs on endpoints.
    local bundle="$STAGE_ROOT/aegis-suite-${VERSION}"
    install -d -m 0755 "$bundle"
    cp "$OUT_DIR/aegis_${VERSION}_amd64.deb" "$bundle/"
    cp "$OUT_DIR/kraken_${VERSION}_amd64.deb" "$bundle/"
    cp "$deb" "$bundle/"
    cp "$ROOT/packaging/server/README.md" "$bundle/README.md"
    cp "$ROOT/docs/AK_CLI.md" "$bundle/AK_CLI.md"
    for extra in \
        "$OUT_DIR/aegis_${VERSION}_amd64.deb.asc" \
        "$OUT_DIR/kraken_${VERSION}_amd64.deb.asc" \
        "$OUT_DIR/aegis-suite_${VERSION}_all.deb.asc" \
        "$OUT_DIR/aegis-agent_${VERSION}_amd64.deb" \
        "$OUT_DIR/aegis-agent_${VERSION}_amd64.deb.asc" \
        "$OUT_DIR/aegis-agent-${VERSION}-x64.msi" \
        "$OUT_DIR/aegis-agent-${VERSION}-x64.msi.cer"; do
        [ -f "$extra" ] && cp "$extra" "$bundle/"
    done

    cat > "$bundle/install.sh" <<'INSTALL'
#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "run this installer as root (sudo)" >&2
    exit 1
fi
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
command -v apt-get >/dev/null 2>&1 || {
    echo "this bundle targets Debian/Ubuntu; install the .deb files with dpkg -i" >&2
    exit 1
}
apt-get install -y \
    "$DIR"/aegis-suite_[0-9]*_all.deb \
    "$DIR"/aegis_[0-9]*_amd64.deb \
    "$DIR"/kraken_[0-9]*_amd64.deb
if command -v ak >/dev/null 2>&1; then
    ak url
fi
if ls "$DIR"/aegis-agent_*_amd64.deb >/dev/null 2>&1; then
    echo "Endpoint agent is included but not installed on this server."
    echo "Install it on each Windows/Linux endpoint, then provision its enrollment token."
fi
INSTALL
    chmod 0755 "$bundle/install.sh"
    ( cd "$bundle" && find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum > SHA256SUMS )
    ( cd "$STAGE_ROOT" && tar -czf "$OUT_DIR/aegis-suite-${VERSION}.tar.gz" \
        "aegis-suite-${VERSION}" )
    ( cd "$OUT_DIR" && sha256sum "aegis-suite-${VERSION}.tar.gz" \
        > "aegis-suite-${VERSION}.tar.gz.sha256" )
    echo "aegis-suite bundle: $OUT_DIR/aegis-suite-${VERSION}.tar.gz"
}

build_aegis
build_kraken
build_suite
