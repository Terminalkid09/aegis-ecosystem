#!/bin/bash
# secure_sandbox.sh
# Questo script applica regole iptables sull'host Docker per impedire ai
# container della sandbox di comunicare con la rete LAN (10.x, 192.168.x, 172.16.x)
# pur permettendo il traffico HTTP/HTTPS verso internet.

if [ "$EUID" -ne 0 ]; then
  echo "Per favore, esegui come root (sudo ./secure_sandbox.sh)"
  exit
fi

SANDBOX_SUBNET="10.20.0.0/24"
LAN_SUBNETS=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")

echo "Configurazione iptables per la rete Sandbox ($SANDBOX_SUBNET)..."

# Inserisci le regole nella chain DOCKER-USER (raccomandato da Docker)
for LAN in "${LAN_SUBNETS[@]}"; do
  # Blocca il traffico dalla sandbox verso la LAN
  iptables -I DOCKER-USER -s $SANDBOX_SUBNET -d $LAN -j DROP
  
  # Blocca il traffico dalla LAN verso la sandbox (opzionale, per massima sicurezza)
  iptables -I DOCKER-USER -s $LAN -d $SANDBOX_SUBNET -j DROP
done

# Permetti il traffico DNS
iptables -I DOCKER-USER -s $SANDBOX_SUBNET -p udp --dport 53 -j ACCEPT
iptables -I DOCKER-USER -s $SANDBOX_SUBNET -p tcp --dport 53 -j ACCEPT

# Permetti il traffico HTTP e HTTPS
iptables -I DOCKER-USER -s $SANDBOX_SUBNET -p tcp --dport 80 -j ACCEPT
iptables -I DOCKER-USER -s $SANDBOX_SUBNET -p tcp --dport 443 -j ACCEPT

# Rifiuta esplicitamente altre porte dal sandbox
iptables -A DOCKER-USER -s $SANDBOX_SUBNET -j REJECT

echo "Regole iptables applicate con successo."
