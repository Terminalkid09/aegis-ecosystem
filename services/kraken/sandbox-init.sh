#!/bin/bash
# Sandbox init script — keeps container alive and accepts commands via stdin
# Commands are received through socat listening on a Unix socket
set -e

SOCKET_PATH=/tmp/sandbox.sock

cleanup() {
    rm -f "$SOCKET_PATH"
    exit 0
}
trap cleanup SIGTERM SIGINT

rm -f "$SOCKET_PATH"

# Listen for commands and execute them
while true; do
    echo "sandbox-ready" | socat - UNIX-LISTEN:"$SOCKET_PATH",fork,reuseaddr EXEC:"/bin/bash -s",pty,stderr,setsid,sigint,sane 2>/dev/null || true
    sleep 1
done
