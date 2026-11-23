#!/bin/sh
# Shared helpers for the local Aegis dashboard port. This file is sourced by
# server-env.sh (first install) and by ak (configure/start), never executed
# directly.

ak_port_in_use() {
    _ak_port="$1"
    case "$_ak_port" in
        ''|*[!0-9]*) return 2 ;;
    esac

    if command -v ss >/dev/null 2>&1; then
        ss -ltnH 2>/dev/null | awk -v p="$_ak_port" '
            { n = split($4, a, ":"); if (a[n] == p) found = 1 }
            END { exit found ? 0 : 1 }
        '
        return $?
    fi

    if command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk -v p="$_ak_port" '
            { n = split($4, a, ":"); if (a[n] == p) found = 1 }
            END { exit found ? 0 : 1 }
        '
        return $?
    fi

    if [ -r /proc/net/tcp ]; then
        _ak_hex="$(printf '%04X' "$_ak_port")"
        awk -v h="$_ak_hex" '
            $4 == "0A" { n = split($2, a, ":"); if (a[n] == h) found = 1 }
            END { exit found ? 0 : 1 }
        ' /proc/net/tcp
        return $?
    fi

    return 1
}

# Print the preferred port when it is free; otherwise the first free port in
# the 3000-3099 dashboard range. Return 1 only when the whole range is busy.
ak_find_free_ui_port() {
    _ak_preferred="${1:-3000}"
    case "$_ak_preferred" in
        ''|*[!0-9]*) _ak_preferred=3000 ;;
    esac

    if ! ak_port_in_use "$_ak_preferred"; then
        printf '%s\n' "$_ak_preferred"
        return 0
    fi

    _ak_candidate=3000
    while [ "$_ak_candidate" -le 3099 ]; do
        if ! ak_port_in_use "$_ak_candidate"; then
            printf '%s\n' "$_ak_candidate"
            return 0
        fi
        _ak_candidate=$((_ak_candidate + 1))
    done

    return 1
}

ak_get_env() {
    _ak_key="$1"
    _ak_file="$2"
    [ -s "$_ak_file" ] || return 0
    sed -n "s/^${_ak_key}=//p" "$_ak_file" | head -n 1
}

ak_set_env() {
    _ak_key="$1"
    _ak_value="$2"
    _ak_file="$3"
    if grep -q "^${_ak_key}=" "$_ak_file" 2>/dev/null; then
        sed -i "s|^${_ak_key}=.*|${_ak_key}=${_ak_value}|" "$_ak_file"
    else
        printf '%s=%s\n' "$_ak_key" "$_ak_value" >> "$_ak_file"
    fi
}

# Add origins to ALLOWED_ORIGINS without discarding operator-defined entries.
ak_add_origins() {
    _ak_file="$1"
    shift
    _ak_origins="$(ak_get_env ALLOWED_ORIGINS "$_ak_file")"
    for _ak_origin in "$@"; do
        [ -n "$_ak_origin" ] || continue
        case ",$_ak_origins," in
            *",$_ak_origin,"*) ;;
            *) _ak_origins="${_ak_origins:+$_ak_origins,}$_ak_origin" ;;
        esac
    done
    ak_set_env ALLOWED_ORIGINS "$_ak_origins" "$_ak_file"
}
