#!/bin/bash
# Start the real xrdp session manager and listener in one disposable container.
set -e

mkdir -p /var/run/xrdp /var/run/dbus /var/log/xrdp
rm -f /var/run/xrdp/*.pid /var/run/dbus/pid 2>/dev/null || true

dbus-daemon --system --fork || true
/usr/sbin/xrdp-sesman --nodaemon &
exec /usr/sbin/xrdp --nodaemon
