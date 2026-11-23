# Kraken multi-node lab (single Docker host)

This overlay runs three independent Kraken sensor containers, each with its own
SSH and HTTP ports, health check and site label. It is the executable part of
the "Lab multi-host" gap that can be reproduced without a second physical host.

It is **not** true multi-host scheduling, network partitioning or automatic
failover. All containers share the Docker engine and kernel. The evidence file
therefore records `single_host: true` and `true_multi_host: false`. A real
multi-host exercise still requires three VMs/hosts and an external orchestrator
plus a way to preserve the attacker source IP.

```bash
python scripts/kraken_lab_multihost.py --build
# evidence under dist/drills/kraken-lab-*.json
python scripts/kraken_lab_multihost.py --down
```

The base stack must be started with the `kraken` profile and have
`KRAKEN_INTERNAL_API_KEY`, `KRAKEN_SECRET_KEY`, etc. in `.env`. Each node uses
`SANDBOX_API_URL=http://aegis-kraken:8000/...`; no sensor mounts the Docker
socket. The probe opens the published HTTP/SSH ports and requires an HTTP 200
and an SSH banner. That proves the listeners are real; it does not prove an
attack event reached the database (that needs the authenticated event API).

## What remains external

- three separate hosts/VMs and network zones;
- a source-IP-preserving ingress (L2/L3 routing, not Docker port mapping);
- an orchestrator with placement/failover (Swarm/K8s/Ansible) if the lab is
  meant to test scheduling;
- an authenticated collector check for each node's event, if the acceptance
  criterion is end-to-end rather than listener reachability.

Do not label this run as "multi-host failure test". The HA drill in
`scripts/ha_failure_drill.sh` covers replica loss on one host; the external
Postgres/Redis failover remains untested until the operator provides those
managed services.
