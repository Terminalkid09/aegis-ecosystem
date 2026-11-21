#!/bin/bash
# Start the real xrdp session manager and listener in one disposable container.
set -e

mkdir -p /var/run/xrdp /var/run/dbus /var/log/xrdp
rm -f /var/run/xrdp/*.pid /var/run/dbus/pid 2>/dev/null || true

# PAM writes authpriv to syslog; run rsyslog so /var/log/auth.log exists for
# the shipper. xrdp's own logs are also watched.
if command -v rsyslogd >/dev/null 2>&1; then
    rsyslogd || true
fi
python3 /usr/local/bin/rdp-log-shipper.py &

dbus-daemon --system --fork || true
/usr/sbin/xrdp-sesman --nodaemon &
exec /usr/sbin/xrdp --nodaemon
