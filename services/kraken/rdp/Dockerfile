FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    dbus-x11 netcat-openbsd python3 rsyslog sudo xfce4 xfce4-terminal xrdp \
    && rm -rf /var/lib/apt/lists/*

# Deliberate weak decoy accounts. They exist only inside this disposable
# container and grant an unprivileged XFCE session, never a host shell.
RUN set -eux; \
    for entry in "administrator:Password123!" "admin:Admin123!" "kraken:Finance2024!"; do \
        user="${entry%%:*}"; pass="${entry#*:}"; \
        useradd -m -s /bin/bash "$user"; \
        echo "$user:$pass" | chpasswd; \
        adduser "$user" ssl-cert || true; \
    done; \
    sed -i 's/^security_layer=.*/security_layer=negotiate/' /etc/xrdp/xrdp.ini; \
    sed -i 's/^crypt_level=.*/crypt_level=high/' /etc/xrdp/xrdp.ini; \
    sed -i 's/^max_bpp=.*/max_bpp=32/' /etc/xrdp/xrdp.ini

COPY rdp/startwm.sh /etc/xrdp/startwm.sh
COPY rdp/entrypoint.sh /usr/local/bin/rdp-entrypoint.sh
COPY rdp/log_shipper.py /usr/local/bin/rdp-log-shipper.py
RUN chmod 0755 /etc/xrdp/startwm.sh /usr/local/bin/rdp-entrypoint.sh /usr/local/bin/rdp-log-shipper.py

EXPOSE 3389
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD bash -c 'echo > /dev/tcp/127.0.0.1/3389'

ENTRYPOINT ["/usr/local/bin/rdp-entrypoint.sh"]
