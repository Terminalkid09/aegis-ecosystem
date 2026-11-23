#!/bin/sh
# ak - operator CLI for the packaged Aegis and Kraken server stacks.
#
# This file is installed as /usr/local/lib/aegis/ak-aegis and
# /usr/local/lib/aegis/ak-kraken. update-alternatives exposes one copy as
# /usr/local/bin/ak, so a standalone install and the suite use the same commands
# without two packages fighting over the same file.
set -u

AK_VERSION="__VERSION__"
# The defaults are the package contract. The AK_* overrides make the CLI
# testable without touching a real server installation; they are not needed by
# normal operators.
SERVER_DIR="${AK_SERVER_DIR:-/opt/aegis/server}"
KRAKEN_DIR="${AK_KRAKEN_DIR:-/opt/aegis/kraken}"
SERVER_ENV="${AK_SERVER_ENV:-/etc/aegis/server.env}"
KRAKEN_ENV="${AK_KRAKEN_ENV:-/etc/aegis/kraken.env}"
SERVER_UNIT="${AK_SERVER_UNIT:-aegis.service}"
KRAKEN_UNIT="${AK_KRAKEN_UNIT:-kraken.service}"
AK_UI_HELPER="${AK_UI_HELPER:-/usr/local/lib/aegis/ui-port.sh}"
AK_REPO="${AK_REPO:-Terminalkid09/aegis-ecosystem}"
AK_UPDATE_BASE_URL="${AK_UPDATE_BASE_URL:-https://github.com/$AK_REPO/releases/download}"
AK_LATEST_URL="${AK_LATEST_URL:-https://github.com/$AK_REPO/releases/latest}"
UPDATE_TMP=""
cleanup_update() {
    [ -z "$UPDATE_TMP" ] || rm -rf "$UPDATE_TMP"
}
trap cleanup_update EXIT HUP INT TERM

if [ -r "$AK_UI_HELPER" ]; then
    # shellcheck disable=SC1090
    . "$AK_UI_HELPER"
fi

usage() {
    cat <<'EOF'
ak - manage the installed Aegis and Kraken server stacks

Usage:
  ak <command> [component] [options]
  ak <component> [command] [options]
  ak help [command]

Components:
  aegis       Aegis server: Brain, Link, dashboard, PostgreSQL, Redis, Caddy
  kraken      Kraken deception stack: app, sensors, broker, RDP, databases
  all         every installed component (default)

Commands:
  start       Start the systemd unit. --wait blocks until containers run.
  stop        Stop the stack. The unit remains enabled for the next boot.
  restart     Stop and start the installed stack.
  status      Show systemd service and boot-enablement state.
  ps          Show the Docker Compose containers and their health.
  logs        Show container logs; use -f to follow and --tail N for a limit.
  doctor      Check systemd, Docker, package files, secrets and memory use.
  url         Print the dashboard/Kraken URLs from the installed env files.
  configure   Set the public hostname, TLS email, dashboard port or URL.
  update      Install a selected release, update the CLI and restart services.
  version     Print the CLI and installed package versions.
  help        Show this help, or detailed help for one command.

Global options:
  -h, --help       Show help and exit 0.
  --version        Same as: ak version.
  help <command>   Detailed help for start, stop, restart, status, ps, logs,
                   doctor, url, configure or update.

Examples:
  sudo ak start
  sudo ak start kraken
  sudo ak kraken restart
  ak status
  ak ps aegis
  ak logs aegis --tail 200
  ak logs aegis -f
  sudo ak configure --domain soc.example.com --email ops@example.com
  sudo ak configure --port 3005
  ak update --check
  sudo ak update --version 4.2.1 --allow-downgrade --yes
  ak url

Privileges:
  start, stop, restart, configure and update require root. status, ps, logs,
  url, doctor and update --check/--dry-run are read-only and do not require
  root, though the Docker socket may restrict access to logs/ps.

Dashboard port and URL:
  The Aegis dashboard binds to 127.0.0.1:${AEGIS_UI_PORT:-3000}. The server
  package picks the first free port in 3000-3099 at install time when 3000 is
  busy. A public URL is configured with AEGIS_DOMAIN, ACME_EMAIL and
  PUBLIC_BASE_URL; use ak configure for changes after installation.

Exit status:
  0  success
  1  a unit, container, port or file operation failed
  2  invalid command, component or option

Files:
  /etc/aegis/server.env       Aegis secrets and public URL settings (0600)
  /etc/aegis/kraken.env       Kraken secrets (0600)
  /opt/aegis/server           Aegis Compose project
  /opt/aegis/kraken           Kraken Compose project
  /usr/local/bin/ak           symlink managed by update-alternatives

The server is headless: installing a .deb does not create a desktop icon.
Open the dashboard in a browser after the stack is healthy. On Windows the
separate aegis-server MSI installs this CLI as ak.cmd; the endpoint agent MSI
does not install it.
EOF
}

command_usage() {
    case "$1" in
        start)
            cat <<'EOF'
Usage: sudo ak start [aegis|kraken|all] [--wait] [--timeout SECONDS]

Start the selected installed systemd units. Without --wait the unit starts with
--no-block and the command returns immediately; the first start builds the
Docker images and can take several minutes. With --wait the unit is started
synchronously and the command polls `docker compose ps` until the component has
at least one running container and no container is starting or unhealthy.
--timeout defaults to 300 seconds and applies per component.

If the dashboard port is occupied while the unit is stopped, ak selects a free
port and records it in /etc/aegis/server.env before starting Aegis.
EOF
            ;;
        stop)
            cat <<'EOF'
Usage: sudo ak stop [aegis|kraken|all]

Stop the selected systemd units. They stay enabled and their containers are
stopped with the Compose project; data volumes and secrets are not removed.
EOF
            ;;
        restart)
            cat <<'EOF'
Usage: sudo ak restart [aegis|kraken|all]

Restart the selected units. Use this after changing /etc/aegis/*.env or after
ak configure. Docker images are rebuilt only when the package upgrade marker
was removed.
EOF
            ;;
        status)
            cat <<'EOF'
Usage: ak status [aegis|kraken|all]

Show systemd active state and boot enablement for each installed component.
This command works without Docker access, but the unit state is only meaningful
on a systemd host.
EOF
            ;;
        ps)
            cat <<'EOF'
Usage: ak ps [aegis|kraken|all]

Show the Docker Compose containers, health and published ports. Requires the
Docker CLI, Compose v2 and permission to access the Docker socket.
EOF
            ;;
        logs)
            cat <<'EOF'
Usage: ak logs [aegis|kraken|all] [--tail N] [-f|--follow]

Show container logs. The default tail is 100 lines. -f follows until Ctrl-C.
EOF
            ;;
        doctor)
            cat <<'EOF'
Usage: ak doctor

Check systemd, the Docker CLI/daemon, Compose v2, installed components, env file
permissions and boot enablement. It also prints the memory budget: host RAM,
the Docker engine limit, live container usage and, inside WSL, a reminder that
the figure includes the VM page cache. It does not start or change anything. A
failed check returns exit status 1 so scripts can gate on it.
EOF
            ;;
        url)
            cat <<'EOF'
Usage: ak url [aegis|kraken|all]

Print the public dashboard URL and the local dashboard URL from server.env,
plus the Kraken endpoint and suite path. The printed URL is the same one used by
Caddy, OIDC callbacks and deployment links.
EOF
            ;;
        configure)
            cat <<'EOF'
Usage: sudo ak configure [options]

Set the Aegis public hostname and local dashboard endpoint. With no options it
prints the current values without changing anything.

Options:
  --domain FQDN       Public DNS name, for example soc.example.com.
  --email ADDRESS     ACME account email; use a real address with a public FQDN.
  --public-url URL    Public origin, for example https://soc.example.com.
  --port PORT         Local 127.0.0.1 dashboard port (1-65535).
  --restart           Restart aegis.service after writing the configuration.
  -h, --help          Show this help.

The command preserves unrelated ALLOWED_ORIGINS entries and adds the new HTTPS
origin, local dashboard origin and Vite development origin. It never rewrites
secrets. If the requested port is already in use, the command fails instead of
silently changing it; use `ak start` to let the start-time fallback choose one.
EOF
            ;;
        version)
            cat <<'EOF'
Usage: ak version

Print the CLI version and the installed aegis/kraken package versions.
EOF
            ;;
        update)
            cat <<'EOF'
Usage: ak update [options]

Install a published release package, which updates both the ak CLI and the
server payload, then restart the installed units. The SHA-256 sidecar must
match before apt/dpkg is allowed to change the host.

Options:
  --version VERSION   Install an explicit version, for example 4.2.1.
  --from DIR|URL      Local directory or release base URL. Default: GitHub release.
  --latest            Resolve the latest published, non-prerelease release.
  --check             Print current and target versions; change nothing.
  --allow-downgrade   Permit an older version after a verified database backup.
  --no-restart        Install packages but do not restart the units.
  --yes               Do not ask for confirmation.
  --dry-run           Resolve and validate without installing.
  -h, --help          Show this help.

Only the current and previous minor lines receive fixes; older versions remain
installable only while their published artifacts exist. See
/usr/share/doc/aegis/RELEASE_POLICY.md or the repository copy.
EOF
            ;;
        *)
            printf 'ak: unknown command: %s\n\n' "$1" >&2
            usage >&2
            return 2
            ;;
    esac
}

die() {
    printf 'ak: %s\n' "$*" >&2
    exit 1
}

usage_error() {
    printf 'ak: %s\n' "$*" >&2
    exit 2
}

installed() {
    case "$1" in
        aegis)  [ -d "$SERVER_DIR" ] ;;
        kraken) [ -d "$KRAKEN_DIR" ] ;;
        *)      return 1 ;;
    esac
}

list_components() {
    case "$1" in
        aegis)
            installed aegis && printf '%s\n' aegis
            ;;
        kraken)
            installed kraken && printf '%s\n' kraken
            ;;
        all)
            installed aegis && printf '%s\n' aegis
            installed kraken && printf '%s\n' kraken
            ;;
        *)
            return 1
            ;;
    esac
}

component_dir() {
    case "$1" in
        aegis)  printf '%s\n' "$SERVER_DIR" ;;
        kraken) printf '%s\n' "$KRAKEN_DIR" ;;
    esac
}

component_env() {
    case "$1" in
        aegis)  printf '%s\n' "$SERVER_ENV" ;;
        kraken) printf '%s\n' "$KRAKEN_ENV" ;;
    esac
}

component_unit() {
    case "$1" in
        aegis)  printf '%s\n' "$SERVER_UNIT" ;;
        kraken) printf '%s\n' "$KRAKEN_UNIT" ;;
    esac
}

env_value() {
    key="$1"
    file="$2"
    [ -s "$file" ] || return 0
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "$1 requires root; try: sudo ak $1"
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 \
        || die "systemctl not found; this CLI manages systemd server units"
    [ -d /run/systemd/system ] \
        || die "systemd is not running here; start the unit on a Linux server with Docker Engine"
}

compose_available() {
    output="$(docker compose version 2>/dev/null || true)"
    case "$output" in
        *"Docker Compose version"*) return 0 ;;
        *) return 1 ;;
    esac
}

daemon_available() {
    server_version="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || true)"
    [ -n "$server_version" ]
}

require_docker() {
    command -v docker >/dev/null 2>&1 \
        || die "docker not found; install Docker Engine with the Compose v2 plugin"
    compose_available \
        || die "docker compose v2 not available; install the Compose plugin"
    daemon_available \
        || die "Docker daemon is not reachable; run 'sudo systemctl enable --now docker' or start Docker Desktop"
}

COMPONENTS=
require_components() {
    requested="$1"
    COMPONENTS="$(list_components "$requested")"
    [ -n "$COMPONENTS" ] \
        || die "no installed component matches '$requested' (install aegis, kraken, or both)"
}

# If a stopped Aegis unit would collide with another process on its recorded
# dashboard port, select a free port before Compose starts. This keeps a normal
# workstation usable even when something else already owns 3000.
aegis_ui_port_guard() {
    [ -s "$SERVER_ENV" ] || return 0
    command -v ak_port_in_use >/dev/null 2>&1 || return 0
    command -v ak_find_free_ui_port >/dev/null 2>&1 || return 0
    command -v systemctl >/dev/null 2>&1 || return 0

    if systemctl is-active --quiet "$SERVER_UNIT" 2>/dev/null; then
        return 0
    fi

    current="$(env_value AEGIS_UI_PORT "$SERVER_ENV")"
    current="${current:-3000}"
    if ! ak_port_in_use "$current"; then
        return 0
    fi

    replacement="$(ak_find_free_ui_port "$current" 2>/dev/null || true)"
    [ -n "$replacement" ] \
        || die "dashboard port $current is busy and no free port exists in 3000-3099"
    ak_set_env AEGIS_UI_PORT "$replacement" "$SERVER_ENV"
    ak_add_origins "$SERVER_ENV" "http://localhost:$replacement"
    chmod 0600 "$SERVER_ENV"
    printf 'ak: dashboard port %s is busy; switched to %s\n' "$current" "$replacement"
}

# Poll the component's Compose project until at least one container is running
# and no container reports a "starting" or "unhealthy" health state. Stopped
# one-shot services (init, sandbox image loaders) are intentionally ignored.
wait_for_component() {
    component="$1"
    limit="$2"
    waited=0
    directory="$(component_dir "$component")"
    env_file="$(component_env "$component")"

    while :; do
        if ( cd "$directory" && docker compose --env-file "$env_file" \
                ps --status running --format '{{.Health}}' 2>/dev/null ) \
            | awk 'NF { total++; if ($1 == "starting" || $1 == "unhealthy") bad = 1 }
                   END { exit (total > 0 && !bad) ? 0 : 1 }'; then
            printf 'Ready %s: %s\n' "$component" \
                "$( cd "$directory" && docker compose --env-file "$env_file" \
                    ps --status running --format '{{.Names}}' 2>/dev/null | wc -l ) container(s) running"
            return 0
        fi
        if [ "$waited" -ge "$limit" ]; then
            die "timed out after ${limit}s waiting for $component; check: ak ps $component and ak logs $component"
        fi
        sleep 5
        waited=$((waited + 5))
    done
}

cmd_start() {
    component="$1"
    shift
    wait_ready=0
    wait_timeout="${AK_START_TIMEOUT:-300}"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --wait)
                wait_ready=1
                shift
                ;;
            --timeout)
                [ "$#" -ge 2 ] || usage_error "--timeout requires seconds"
                wait_timeout="$2"
                shift 2
                ;;
            *)
                usage_error "unknown start option: $1"
                ;;
        esac
    done
    case "$wait_timeout" in
        ''|*[!0-9]*) usage_error "--timeout must be a number of seconds" ;;
    esac

    require_root start
    require_systemd
    require_docker
    require_components "$component"
    case "$COMPONENTS" in
        *aegis*) aegis_ui_port_guard ;;
    esac
    for component in $COMPONENTS; do
        unit="$(component_unit "$component")"
        printf 'Starting %s (%s)...\n' "$component" "$unit"
        if [ "$wait_ready" -eq 1 ]; then
            systemctl start "$unit" || die "systemctl start $unit failed"
            wait_for_component "$component" "$wait_timeout"
        else
            systemctl start --no-block "$unit" || die "systemctl start $unit failed"
            printf 'Started %s; the first start builds images. Check with: ak status\n' "$component"
        fi
    done
}

cmd_stop() {
    require_root stop
    require_systemd
    require_components "$1"
    for component in $COMPONENTS; do
        unit="$(component_unit "$component")"
        printf 'Stopping %s (%s)...\n' "$component" "$unit"
        systemctl stop "$unit" || die "systemctl stop $unit failed"
    done
}

cmd_restart() {
    require_root restart
    require_systemd
    require_docker
    require_components "$1"
    case "$COMPONENTS" in
        *aegis*) aegis_ui_port_guard ;;
    esac
    for component in $COMPONENTS; do
        unit="$(component_unit "$component")"
        printf 'Restarting %s (%s)...\n' "$component" "$unit"
        systemctl restart "$unit" || die "systemctl restart $unit failed"
    done
}

cmd_status() {
    require_components "$1"
    for component in $COMPONENTS; do
        unit="$(component_unit "$component")"
        active=unknown
        enabled=unknown
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            active="$(systemctl is-active "$unit" 2>/dev/null || true)"
            enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        fi
        printf '%-8s service=%-10s boot=%s\n' "$component" "$active" "$enabled"
    done
    printf '\nContainer details: ak ps [component]\n'
}

cmd_ps() {
    require_docker
    require_components "$1"
    rc=0
    for component in $COMPONENTS; do
        directory="$(component_dir "$component")"
        env_file="$(component_env "$component")"
        printf '== %s ==\n' "$component"
        ( cd "$directory" && docker compose --env-file "$env_file" ps ) || rc=1
    done
    return "$rc"
}

cmd_logs() {
    component="$1"
    shift
    follow=0
    tail_lines=100

    while [ "$#" -gt 0 ]; do
        case "$1" in
            -f|--follow)
                follow=1
                shift
                ;;
            --tail)
                [ "$#" -ge 2 ] || usage_error "--tail requires a number"
                tail_lines="$2"
                shift 2
                ;;
            -n)
                [ "$#" -ge 2 ] || usage_error "-n requires a number"
                tail_lines="$2"
                shift 2
                ;;
            *)
                usage_error "unknown logs option: $1"
                ;;
        esac
    done

    require_docker
    require_components "$component"
    rc=0
    for name in $COMPONENTS; do
        directory="$(component_dir "$name")"
        env_file="$(component_env "$name")"
        printf '== %s ==\n' "$name"
        if [ "$follow" -eq 1 ]; then
            ( cd "$directory" && docker compose --env-file "$env_file" logs --tail "$tail_lines" -f ) || rc=1
        else
            ( cd "$directory" && docker compose --env-file "$env_file" logs --tail "$tail_lines" ) || rc=1
        fi
    done
    return "$rc"
}

cmd_doctor() {
    rc=0

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf 'OK    systemd is running\n'
    else
        printf 'FAIL  systemd is not running; server units cannot start\n'
        rc=1
    fi

    if command -v docker >/dev/null 2>&1; then
        printf 'OK    docker CLI found\n'
        if compose_available; then
            printf 'OK    docker compose v2 found\n'
        else
            printf 'FAIL  docker compose v2 not found\n'
            rc=1
        fi
        if compose_available; then
            if daemon_available; then
                printf 'OK    Docker daemon is reachable\n'
            else
                printf 'WARN  Docker daemon is not reachable (or this user cannot access the socket)\n'
            fi
        else
            printf 'SKIP  Docker daemon check (Compose v2 is missing)\n'
        fi
    else
        printf 'FAIL  docker CLI not found\n'
        rc=1
    fi

    if [ "$(id -u)" -eq 0 ]; then
        printf 'OK    running as root (lifecycle commands available)\n'
    else
        printf 'WARN  not root; start/stop/restart need sudo\n'
    fi

    printf '\nResources:\n'
    if [ -r /proc/meminfo ]; then
        awk '/^MemTotal:/ { printf "INFO  host memory: %.1f GiB\n", $2 / 1048576 }
             /^MemAvailable:/ { printf "INFO  host memory available: %.1f GiB\n", $2 / 1048576 }' \
            /proc/meminfo
    fi
    if grep -qi microsoft /proc/version 2>/dev/null; then
        printf 'INFO  WSL detected: this is the VM ceiling, not Aegis usage. Set\n'
        printf '      memory= and autoMemoryReclaim=gradual in %%USERPROFILE%%\\.wslconfig.\n'
    fi
    if command -v docker >/dev/null 2>&1 && daemon_available; then
        engine_mem="$(docker info --format '{{.MemTotal}}' 2>/dev/null || true)"
        engine_cpu="$(docker info --format '{{.NCPU}}' 2>/dev/null || true)"
        case "$engine_mem" in
            ''|*[!0-9]*) ;;
            *) awk -v mem="$engine_mem" -v cpu="$engine_cpu" \
                'BEGIN { printf "INFO  Docker engine limit: %.1f GiB across %s CPU\n", mem / 1073741824, cpu }' ;;
        esac
        docker stats --no-stream --format 'INFO  usage {{.Name}}: {{.MemUsage}} ({{.MemPerc}})' 2>/dev/null \
            | head -n 12
    fi

    require_components all
    for component in $COMPONENTS; do
        env_file="$(component_env "$component")"
        unit="$(component_unit "$component")"
        if [ -s "$env_file" ]; then
            mode="$(stat -c '%a' "$env_file" 2>/dev/null || printf 'unknown')"
            if [ "$mode" = "600" ]; then
                printf 'OK    %s env exists with mode 600\n' "$component"
            else
                printf 'WARN  %s env mode is %s (expected 600)\n' "$component" "$mode"
            fi
        else
            printf 'FAIL  %s env file is missing: %s\n' "$component" "$env_file"
            rc=1
        fi
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
                printf 'OK    %s is enabled at boot\n' "$component"
            else
                printf 'FAIL  %s is not enabled at boot\n' "$component"
                rc=1
            fi
        fi
    done

    return "$rc"
}

cmd_url() {
    require_components "$1"
    for component in $COMPONENTS; do
        case "$component" in
            aegis)
                public_url="$(env_value PUBLIC_BASE_URL "$SERVER_ENV")"
                [ -n "$public_url" ] || public_url="https://aegis.local"
                ui_port="$(env_value AEGIS_UI_PORT "$SERVER_ENV")"
                [ -n "$ui_port" ] || ui_port=3000
                printf 'Aegis dashboard: %s/  (local: http://localhost:%s)\n' \
                    "${public_url%/}" "$ui_port"
                ;;
            kraken)
                port="$(env_value KRAKEN_PORT_EXTERNAL "$KRAKEN_ENV")"
                [ -n "$port" ] || port=8001
                base="$(env_value KRAKEN_PUBLIC_BASE_PATH "$KRAKEN_ENV")"
                [ -n "$base" ] || base=""
                printf 'Kraken: http://127.0.0.1:%s%s/  (suite: via Aegis Caddy)\n' \
                    "$port" "${base%/}"
                ;;
        esac
    done
}

valid_hostname() {
    host="$1"
    [ -n "$host" ] && [ ${#host} -le 253 ] || return 1
    case "$host" in
        .*|*.|*..*) return 1 ;;
    esac
    old_ifs="$IFS"
    IFS=.
    for label in $host; do
        [ -n "$label" ] && [ ${#label} -le 63 ] || {
            IFS="$old_ifs"
            return 1
        }
        case "$label" in
            -*|*-|*[!A-Za-z0-9-]*)
                IFS="$old_ifs"
                return 1
                ;;
        esac
    done
    IFS="$old_ifs"
    return 0
}

valid_email() {
    case "$1" in
        internal) return 0 ;;
        *[!A-Za-z0-9@._+-]*|*@*@*|@*|*@) return 1 ;;
    esac
    case "$1" in
        *@*.*) return 0 ;;
    esac
    return 1
}

is_local_domain() {
    case "$1" in
        localhost|*.local) return 0 ;;
    esac
    return 1
}

cmd_configure() {
    require_components aegis
    [ -s "$SERVER_ENV" ] || die "Aegis env file is missing: $SERVER_ENV"

    domain=""
    email=""
    port=""
    public_url=""
    restart=0
    changed=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --domain)
                [ "$#" -ge 2 ] || usage_error "--domain requires a hostname"
                domain="$2"
                changed=1
                shift 2
                ;;
            --email)
                [ "$#" -ge 2 ] || usage_error "--email requires an address"
                email="$2"
                changed=1
                shift 2
                ;;
            --port)
                [ "$#" -ge 2 ] || usage_error "--port requires a number"
                port="$2"
                changed=1
                shift 2
                ;;
            --public-url)
                [ "$#" -ge 2 ] || usage_error "--public-url requires an origin"
                public_url="$2"
                changed=1
                shift 2
                ;;
            --restart)
                restart=1
                shift
                ;;
            --no-restart)
                restart=0
                shift
                ;;
            -h|--help)
                command_usage configure
                return 0
                ;;
            *)
                usage_error "unknown configure option: $1"
                ;;
        esac
    done

    current_domain="$(env_value AEGIS_DOMAIN "$SERVER_ENV")"
    [ -n "$current_domain" ] || current_domain=aegis.local
    current_email="$(env_value ACME_EMAIL "$SERVER_ENV")"
    [ -n "$current_email" ] || current_email=internal
    current_port="$(env_value AEGIS_UI_PORT "$SERVER_ENV")"
    [ -n "$current_port" ] || current_port=3000
    current_public="$(env_value PUBLIC_BASE_URL "$SERVER_ENV")"
    [ -n "$current_public" ] || current_public="https://$current_domain"

    if [ "$changed" -eq 0 ]; then
        printf 'Aegis domain:  %s\n' "$current_domain"
        printf 'ACME email:   %s\n' "$current_email"
        printf 'Public URL:   %s\n' "${current_public%/}"
        printf 'Local URL:    http://localhost:%s\n' "$current_port"
        return 0
    fi

    require_root configure

    new_domain="${domain:-$current_domain}"
    new_email="${email:-$current_email}"
    new_port="${port:-$current_port}"
    new_public="${public_url:-$current_public}"

    if [ -n "$public_url" ] && [ -z "$domain" ]; then
        derived="${new_public#*://}"
        derived="${derived%%/*}"
        derived="${derived%%:*}"
        [ -n "$derived" ] || usage_error "cannot derive a hostname from $new_public"
        new_domain="$derived"
    elif [ -n "$domain" ] && [ -z "$public_url" ]; then
        new_public="https://$new_domain"
    fi

    valid_hostname "$new_domain" \
        || usage_error "invalid hostname: $new_domain"
    valid_email "$new_email" \
        || usage_error "invalid email: $new_email"
    if ! is_local_domain "$new_domain" && [ "$new_email" = "internal" ]; then
        usage_error "a public FQDN requires a real ACME email"
    fi
    case "$new_port" in
        ''|*[!0-9]*)
            usage_error "invalid port: $new_port"
            ;;
    esac
    [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ] \
        || usage_error "port must be between 1 and 65535"

    case "$new_public" in
        http://*|https://*) ;;
        *) usage_error "public URL must start with http:// or https://" ;;
    esac
    new_public="${new_public%/}"
    public_host="${new_public#*://}"
    public_host="${public_host%%/*}"
    public_host="${public_host%%:*}"
    [ "$public_host" = "$new_domain" ] \
        || usage_error "public URL host $public_host does not match AEGIS_DOMAIN $new_domain"

    if [ "$new_port" != "$current_port" ] \
        && command -v ak_port_in_use >/dev/null 2>&1 \
        && ak_port_in_use "$new_port"; then
        die "port $new_port is already in use; stop the other process or choose another port"
    fi

    ak_set_env AEGIS_DOMAIN "$new_domain" "$SERVER_ENV"
    ak_set_env ACME_EMAIL "$new_email" "$SERVER_ENV"
    ak_set_env AEGIS_UI_PORT "$new_port" "$SERVER_ENV"
    ak_set_env PUBLIC_BASE_URL "$new_public" "$SERVER_ENV"
    ak_add_origins "$SERVER_ENV" "https://$new_domain" \
        "http://localhost:$new_port" "http://localhost:5173" "$new_public"
    chmod 0600 "$SERVER_ENV"
    chown root:root "$SERVER_ENV" 2>/dev/null || true

    printf 'Configured Aegis: %s (local http://localhost:%s)\n' \
        "$new_public" "$new_port"

    if [ "$restart" -eq 1 ]; then
        require_systemd
        require_docker
        systemctl restart "$SERVER_UNIT" || die "systemctl restart $SERVER_UNIT failed"
        printf 'Restarted %s\n' "$SERVER_UNIT"
    else
        printf 'Apply with: sudo ak restart aegis\n'
    fi
}

latest_version() {
    command -v curl >/dev/null 2>&1 \
        || die "curl is required to resolve the latest release; use --version or --from"
    final_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$AK_LATEST_URL" 2>/dev/null || true)"
    case "$final_url" in
        */tag/v[0-9]*.[0-9]*.[0-9]*) ;;
        *) die "cannot resolve the latest release from $AK_LATEST_URL" ;;
    esac
    version="${final_url##*/tag/v}"
    normalize_version "$version" \
        || die "latest release has an invalid version: $version"
}

normalize_version() {
    value="${1#v}"
    valid_version "$value" || return 1
    printf '%s\n' "$value"
}

valid_version() {
    case "$1" in
        [0-9]*.[0-9]*.[0-9]*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!0-9.]*|.*|*..*|*.) return 1 ;;
    esac
    return 0
}

update_edition() {
    if dpkg-query -W -f='${Status}' aegis-suite 2>/dev/null | grep -q 'install ok installed'; then
        printf 'suite\n'
    elif installed aegis && installed kraken; then
        printf 'both\n'
    elif installed aegis; then
        printf 'aegis\n'
    elif installed kraken; then
        printf 'kraken\n'
    else
        die "no installed server component found"
    fi
}

update_current_version() {
    package="$1"
    dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true
}

cmd_update() {
    target=""
    source=""
    check=0
    latest=0
    assume_yes=0
    dry_run=0
    restart=1
    allow_downgrade=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || usage_error "--version requires a version"
                target="$2"
                shift 2
                ;;
            --from)
                [ "$#" -ge 2 ] || usage_error "--from requires a directory or URL"
                source="$2"
                shift 2
                ;;
            --latest)
                latest=1
                shift
                ;;
            --check)
                check=1
                shift
                ;;
            --allow-downgrade)
                allow_downgrade=1
                shift
                ;;
            --no-restart)
                restart=0
                shift
                ;;
            --yes)
                assume_yes=1
                shift
                ;;
            --dry-run)
                dry_run=1
                shift
                ;;
            -h|--help)
                command_usage update
                return 0
                ;;
            *)
                usage_error "unknown update option: $1"
                ;;
        esac
    done

    if [ -n "$target" ] && [ "$latest" -eq 1 ]; then
        usage_error "use --version or --latest, not both"
    fi
    if [ -z "$target" ]; then
        if [ -n "$source" ]; then
            usage_error "--from requires --version so the release is unambiguous"
        fi
        target="$(latest_version)"
    fi
    target="$(normalize_version "$target")" \
        || usage_error "invalid version: $target (expected MAJOR.MINOR.PATCH)"

    edition="$(update_edition)"
    case "$edition" in
        aegis) current="$(update_current_version aegis)" ;;
        kraken) current="$(update_current_version kraken)" ;;
        both) current="$(update_current_version aegis)" ;;
        suite) current="$(update_current_version aegis-suite)" ;;
    esac
    [ -n "$current" ] \
        || die "cannot determine the installed package version"
    current="$(normalize_version "$current")" \
        || die "installed package has an invalid version: $current"

    if [ "$check" -eq 1 ]; then
        printf 'Installed: %s %s\n' "$edition" "$current"
        printf 'Target:    %s %s\n' "$edition" "$target"
        if dpkg --compare-versions "$target" lt "$current"; then
            printf 'Target is older; use --allow-downgrade and a verified database backup.\n'
        fi
        return 0
    fi

    if dpkg --compare-versions "$target" lt "$current" \
        && [ "$allow_downgrade" -ne 1 ]; then
        die "refusing to downgrade from $current to $target without --allow-downgrade and a verified database backup"
    fi

    case "$edition" in
        aegis) packages="aegis_${target}_amd64.deb" ;;
        kraken) packages="kraken_${target}_amd64.deb" ;;
        both) packages="aegis_${target}_amd64.deb kraken_${target}_amd64.deb" ;;
        suite) packages="aegis-suite_${target}_all.deb aegis_${target}_amd64.deb kraken_${target}_amd64.deb" ;;
    esac

    source_dir=""
    source_base=""
    if [ -n "$source" ]; then
        case "$source" in
            http://*|https://*) source_base="${source%/}" ;;
            *) [ -d "$source" ] || die "--from is neither an existing directory nor an http(s) URL: $source"; source_dir="$source" ;;
        esac
    else
        source_base="$AK_UPDATE_BASE_URL/v$target"
    fi

    printf 'Update: %s %s -> %s\n' "$edition" "$current" "$target"
    printf 'Packages: %s\n' "$packages"
    [ -n "$source_dir" ] && printf 'Source: %s\n' "$source_dir"
    [ -n "$source_base" ] && printf 'Source: %s\n' "$source_base"

    if [ "$dry_run" -eq 1 ]; then
        printf 'Dry run: no packages changed.\n'
        return 0
    fi

    require_root update
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
    if [ -n "$source_base" ]; then
        command -v curl >/dev/null 2>&1 || die "curl is required from a release URL"
    fi

    UPDATE_TMP="$(mktemp -d)"
    set --
    for package in $packages; do
        if [ -n "$source_dir" ]; then
            artifact="$source_dir/$package"
            sidecar="$artifact.sha256"
        else
            artifact="$UPDATE_TMP/$package"
            sidecar="$artifact.sha256"
            curl -fsSL "$source_base/$package" -o "$artifact" \
                || die "download failed: $source_base/$package"
            curl -fsSL "$source_base/$package.sha256" -o "$sidecar" \
                || die "checksum download failed: $source_base/$package.sha256"
        fi
        [ -f "$artifact" ] || die "release package not found: $artifact"
        [ -f "$sidecar" ] || die "SHA-256 sidecar not found: $sidecar"
        expected="$(awk 'NR == 1 {print $1}' "$sidecar" | tr -d '\r')"
        actual="$(sha256sum "$artifact" | awk '{print $1}')"
        case "$expected" in
            [0-9A-Fa-f][0-9A-Fa-f]*) ;;
            *) die "invalid SHA-256 sidecar: $sidecar" ;;
        esac
        [ "${#expected}" -eq 64 ] || die "invalid SHA-256 sidecar: $sidecar"
        [ "$actual" = "$expected" ] \
            || die "SHA-256 mismatch for $package (expected $expected, got $actual)"
        printf 'Verified %s\n' "$package"
        set -- "$@" "$artifact"
    done

    printf 'Install: %s\n' "$packages"
    if [ "$assume_yes" -ne 1 ]; then
        [ -t 0 ] || die "confirmation required; re-run with --yes"
        printf 'Install these packages and replace the running server? [y/N] '
        read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) printf 'Update cancelled.\n'; return 0 ;;
        esac
    fi

    # An update must never block on a debconf or conffile prompt: the operator
    # already confirmed the release, and the env files are generated outside the
    # package. Keep a caller-provided DEBIAN_FRONTEND override.
    if command -v apt-get >/dev/null 2>&1 \
        && apt-get --help 2>&1 | grep -q -- '--allow-downgrades'; then
        DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}" \
        APT_LISTCHANGES_FRONTEND=none \
        apt-get install -y --allow-downgrades \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold "$@" \
            || die "package installation failed"
    else
        command -v dpkg >/dev/null 2>&1 || die "apt-get/dpkg not found"
        DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}" \
        dpkg --force-confdef --force-confold -i "$@" \
            || die "package installation failed"
    fi

    if [ "$restart" -eq 1 ]; then
        require_systemd
        for component in $(list_components all); do
            printf 'Restarting %s (%s)...\n' "$component" "$(component_unit "$component")"
            systemctl restart "$(component_unit "$component")" \
                || die "updated, but systemctl restart $component failed"
        done
    else
        printf 'Packages installed. Apply with: sudo ak restart\n'
    fi
    printf 'Updated %s to %s.\n' "$edition" "$target"
}

cmd_version() {
    printf 'ak %s\n' "$AK_VERSION"
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Package} ${Version}\n' aegis kraken 2>/dev/null || true
    fi
}

main() {
    [ "$#" -gt 0 ] || {
        usage
        exit 0
    }

    command="$1"
    shift
    component=all

    case "$command" in
        aegis|kraken|all)
            component="$command"
            if [ "$#" -gt 0 ]; then
                command="$1"
                shift
            else
                command=status
            fi
            ;;
    esac

    case "$command" in
        start|stop|restart|status|ps|url)
            if [ "$#" -gt 0 ]; then
                case "$1" in
                    aegis|kraken|all)
                        component="$1"
                        shift
                        ;;
                    -h|--help)
                        command_usage "$command"
                        return 0
                        ;;
                    --*)
                        # start parses --wait/--timeout itself; other commands
                        # have no options and must not swallow them silently.
                        [ "$command" = "start" ] \
                            || usage_error "unknown option: $1"
                        ;;
                    *)
                        usage_error "unknown component: $1 (use aegis, kraken, or all)"
                        ;;
                esac
            fi
            ;;
        logs)
            case "${1:-}" in
                -h|--help)
                    command_usage logs
                    return 0
                    ;;
                aegis|kraken|all)
                    component="$1"
                    shift
                    ;;
                ""|-*)
                    ;;
                *)
                    usage_error "unknown component: $1 (use aegis, kraken, or all)"
                    ;;
            esac
            ;;
        configure|config|setup)
            case "${1:-}" in
                -h|--help)
                    command_usage configure
                    return 0
                    ;;
            esac
            ;;
        update)
            case "${1:-}" in
                -h|--help)
                    command_usage update
                    return 0
                    ;;
            esac
            ;;
    esac

    case "$command" in
        help|-h|--help)
            if [ "$#" -gt 0 ]; then
                command_usage "$1" || exit $?
            else
                usage
            fi
            ;;
        version|--version)
            cmd_version
            ;;
        start)
            cmd_start "$component" "$@"
            ;;
        stop)
            cmd_stop "$component"
            ;;
        restart)
            cmd_restart "$component"
            ;;
        status)
            cmd_status "$component"
            ;;
        ps)
            cmd_ps "$component"
            ;;
        logs)
            cmd_logs "$component" "$@"
            ;;
        doctor)
            cmd_doctor
            ;;
        url)
            cmd_url "$component"
            ;;
        configure|config|setup)
            cmd_configure "$@"
            ;;
        update)
            [ "$component" = "all" ] \
                || usage_error "ak update updates the installed packages; do not pass a component"
            cmd_update "$@"
            ;;
        *)
            printf 'ak: unknown command: %s\n\n' "$command" >&2
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"
