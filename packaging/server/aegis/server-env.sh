#!/bin/sh
set -eu

# The package installs this helper next to this script. The fallback keeps the
# script usable from a source checkout during development.
HELPER_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -r "$HELPER_DIR/ui-port.sh" ]; then
    . "$HELPER_DIR/ui-port.sh"
elif [ -r /usr/local/lib/aegis/ui-port.sh ]; then
    . /usr/local/lib/aegis/ui-port.sh
fi

rand() {
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

# A customer can preseed these through debconf or pass them as environment
# variables to dpkg/apt. AEGIS_PUBLIC_URL is optional; the default origin is
# https://<domain> and is what OIDC/deployment links use.
valid_hostname() {
    host="$1"
    [ -n "$host" ] && [ ${#host} -le 253 ] || return 1
    case "$host" in .*|*.|*..*) return 1 ;; esac
    old_ifs="$IFS"
    IFS=.
    for label in $host; do
        [ -n "$label" ] && [ ${#label} -le 63 ] || { IFS="$old_ifs"; return 1; }
        case "$label" in -*|*-|*[!A-Za-z0-9-]*) IFS="$old_ifs"; return 1 ;; esac
    done
    IFS="$old_ifs"
    return 0
}

valid_email() {
    case "$1" in
        internal) return 0 ;;
        *[!A-Za-z0-9@._+-]*|*@*@*|@*|*@) return 1 ;;
    esac
    case "$1" in *@*.*) return 0 ;; esac
    return 1
}

is_local_domain() {
    case "$1" in localhost|*.local) return 0 ;; esac
    return 1
}

domain="${AEGIS_DOMAIN:-aegis.local}"
public_url="${AEGIS_PUBLIC_URL:-}"
if [ -n "$public_url" ]; then
    public_url="${public_url%/}"
    case "$public_url" in
        http://*|https://*) ;;
        *)
            printf 'AEGIS_PUBLIC_URL must start with http:// or https://\n' >&2
            exit 2
            ;;
    esac
    if [ -z "${AEGIS_DOMAIN:-}" ]; then
        domain="${public_url#*://}"
        domain="${domain%%/*}"
        domain="${domain%%:*}"
    fi
else
    public_url="https://$domain"
fi

valid_hostname "$domain" \
    || { printf 'AEGIS_DOMAIN is not a valid hostname: %s\n' "$domain" >&2; exit 2; }

acme_email="${ACME_EMAIL:-internal}"
valid_email "$acme_email" \
    || { printf 'ACME_EMAIL is not a valid address: %s\n' "$acme_email" >&2; exit 2; }
if ! is_local_domain "$domain" && [ "$acme_email" = "internal" ]; then
    printf 'ACME_EMAIL must be a real address for public FQDN %s\n' "$domain" >&2
    exit 2
fi

if [ -n "$public_url" ]; then
    public_host="${public_url#*://}"
    public_host="${public_host%%/*}"
    public_host="${public_host%%:*}"
    if [ "$public_host" != "$domain" ]; then
        printf 'AEGIS_PUBLIC_URL host %s does not match AEGIS_DOMAIN %s\n' \
            "$public_host" "$domain" >&2
        exit 2
    fi
fi
ui_port="${AEGIS_UI_PORT:-3000}"
case "$ui_port" in
    ''|*[!0-9]*)
        printf 'AEGIS_UI_PORT must be a TCP port number (1-65535)\n' >&2
        exit 2
        ;;
esac
if [ "$ui_port" -lt 1 ] || [ "$ui_port" -gt 65535 ]; then
    printf 'AEGIS_UI_PORT must be between 1 and 65535\n' >&2
    exit 2
fi

# The dashboard is commonly installed on a workstation where port 3000 is
# already used. Prefer the requested port, then take the first free port in the
# documented 3000-3099 range. The selected value is written to the env file, so
# ak url and the Compose file always agree.
if command -v ak_find_free_ui_port >/dev/null 2>&1; then
    selected_ui_port="$(ak_find_free_ui_port "$ui_port" || true)"
    if [ -z "$selected_ui_port" ]; then
        printf 'no free dashboard port in 3000-3099; set AEGIS_UI_PORT to a free port\n' >&2
        exit 2
    fi
    if [ "$selected_ui_port" != "$ui_port" ]; then
        printf 'dashboard port %s is busy; using %s\n' "$ui_port" "$selected_ui_port" >&2
    fi
    ui_port="$selected_ui_port"
fi

origins="https://$domain,http://localhost:$ui_port,http://localhost:5173"
case ",$origins," in
    *",$public_url,"*) ;;
    *) origins="$origins,$public_url" ;;
esac

pw="$(rand 16)"
redis_pw="$(rand 16)"
api_key="$(rand 32)"
enroll_key="$(rand 16)"
jwt_secret="$(rand 32)"
master_key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
backup_passphrase="$(rand 16)"

cat <<EOF
COMPOSE_PROJECT_NAME=aegis
POSTGRES_USER=aegis_user
POSTGRES_PASSWORD=$pw
POSTGRES_DB=aegis_db
DATABASE_URL=postgresql+asyncpg://aegis_user:$pw@aegis-postgres:5432/aegis_db
REDIS_PASSWORD=$redis_pw
REDIS_URL=redis://:$redis_pw@aegis-redis:6379
REDIS_HOST=aegis-redis
REDIS_PORT=6379
POSTGRES_PORT=5444
BRAIN_PORT_EXTERNAL=8000
LINK_PORT_EXTERNAL=8088
OLLAMA_PORT_EXTERNAL=11435
AEGIS_API_KEY=$api_key
AGENT_ENROLL_KEY=$enroll_key
JWT_SECRET=$jwt_secret
MASTER_KEY_B64=$master_key
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
AEGIS_DEBUG=false
AEGIS_ALLOW_OPEN_REGISTRATION=false
AEGIS_COOKIE_SECURE=true
AEGIS_DOMAIN=$domain
ACME_EMAIL=$acme_email
ALLOWED_ORIGINS=$origins
PUBLIC_BASE_URL=$public_url
AEGIS_UI_PORT=$ui_port
VITE_API_URL=/api/v1
BACKUP_PASSPHRASE=$backup_passphrase
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
EOF
