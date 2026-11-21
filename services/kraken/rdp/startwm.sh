#!/bin/sh
# Minimal XFCE session for the RDP honeypot. It intentionally exposes no host
# filesystem beyond the container and no credentials from the Kraken stack.
set -e
if [ -r /etc/default/locale ]; then
    . /etc/default/locale
    export LANG LANGUAGE
fi
exec startxfce4
