#!/bin/sh
set -eu

if [ ! -f /etc/nginx/ssl/key.pem ] || [ ! -f /etc/nginx/ssl/cert.pem ]; then
    if [ "${PROFILE:-prod}" = "lab" ]; then
        echo "LAB profile: generating a self-signed SSL certificate."
        apk add --no-cache openssl >/dev/null 2>&1
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/key.pem \
            -out /etc/nginx/ssl/cert.pem \
            -subj "/C=IT/ST=State/L=City/O=Kraken/CN=localhost" 2>/dev/null
        echo "Self-signed certificate generated."
    else
        echo "FATAL: TLS certificate missing. Mount cert.pem/key.pem or use PROFILE=lab." >&2
        exit 1
    fi
fi

exec nginx -g "daemon off;"
