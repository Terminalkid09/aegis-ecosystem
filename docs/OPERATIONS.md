# Aegis — Operazioni on-premise (M8 Fase 9)

Runbook operatore: installazione pulita, backup/restore, upgrade/rollback,
PKI bootstrap, retention. Comandi per Docker Compose (profilo `backup` per
il servizio di backup). Mai segreti in repo: solo `.env` esterno.

## 1. Installazione pulita

```bash
cp .env.example .env   # + valorizza TUTTI i replace-with-*
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose ps                    # tutti healthy
curl -sk https://aegis.local/api/v1/health  # {"status":"ok"}
```

Prerequisiti: Docker + Compose v2, Python 3.10+ per `scripts/run_integration_tests.py`,
`POSTGRES_PORT`/`REDIS_PORT_EXTERNAL` raggiungibili su 127.0.0.1. Vedi
`scripts/run_integration_tests.py --help` e `aegis-brain/tests/conftest.py`
(`TEST_DATABASE_URL`/`REQUIRE_INTEGRATION=1` per CI fail-closed).

Verifiche: `GET /health/live|ready|startup` sul brain; Caddy con certificato
reale in prod (sostituire `tls internal` nel Caddyfile con email ACME).

## 1b. Enrollment token e servizi host

Da **Deployment Manager** creare un token per `Aegis-Guard`, `NodeTrace` o
`Both agents`. Il token è breve e monouso per ogni tipo di agent: con `Both`
Guard e NodeTrace effettuano due enrollment separati sullo stesso host.

Il comando generato:

- scarica l'artefatto dal Brain usando il token bootstrap;
- configura l'URL del Brain e le URL di enrollment/heartbeat;
- registra `AegisGuard`/`AegisNodeTrace` come servizi Windows, oppure crea le
  unità systemd equivalenti su Linux;
- abilita l'avvio automatico, il restart dopo crash e verifica lo stato del
  servizio prima di terminare con successo.

La connessione alla dashboard remota è opzionale. Se disattivata, i file
vengono estratti ma i servizi non vengono avviati, perché un agent senza
endpoint di enrollment configurato non deve partire in modo ambiguo.

**Prima degli installer: pubblicare gli artefatti.** L'one-liner scarica da
`/deploy/bootstrap-artifacts/<agent>-latest.zip`, quindi il file deve esistere
in `ARTIFACT_DIR` (gli artefatti sono output di build: non stanno nel repo).

```bash
python scripts/pack-artifacts.py            # ZIP + tar.gz, nomi -latest inclusi
python scripts/setup.py update --rebuild-agents   # se serve ricostruire prima
```

Dentro l'artefatto di Guard finiscono `aegis-guard.jar`, il `jre/` incluso
(se `build.bat` lo ha creato), `aegis-etw.exe` per la telemetria kernel e
`bin/yara64.exe`. Manca il runtime → lo script fallisce; manca un pezzo
opzionale (collector ETW, YARA) → lo dichiara e Guard degrada dicendolo
(`quality=degraded:etw-...`). Sul target serve **admin** (registrazione
servizio + sessione di trace ETW) e **Java 21+**, incluso nell'artefatto o
installato lì: la versione viene verificata, non solo la presenza (`java` 8
avviva un servizio che muore con `UnsupportedClassVersionError`).

La dashboard locale sull'endpoint non è ancora distribuita: non selezionarla
come requisito operativo. Per aziende isolate usare una dashboard centrale
raggiungibile dalla rete interna; il supporto a una dashboard locale richiede
un bundle statico, un server locale e una configurazione API autenticata.

## 2. PKI bootstrap (una volta, prima degli agent)

```bash
docker compose exec aegis-brain python -m app.services.pki --dir /app/pki
# -> CA in /app/pki/ca.crt + chiave manifest; distribuire la pubkey_b64
#    stampata come AEGIS_MANIFEST_PUBKEY agli agent (env/GPO/Intune).
```

Volume consigliato: montare `/app/pki` su storage persistente separato e
includerlo nei backup cifrati (senza CA niente nuove firme).

### 2b. Rollout mTLS agent (pilot)

1. `python -m app.services.pki --dir /app/pki` (CA + chiave manifest).
2. Agent: enrollment esistente, poi l'agent genera la chiave localmente e
   chiama `POST /enroll/csr` (autenticato col device secret) → certificato
   device (CN=agent_id). Revoca: `POST /enroll/agents/{id}/revoke`.
3. Validare il terminatore: `caddy validate` con `Caddyfile.mtls`
   (listener :8443 `require_and_verify` contro `/etc/caddy/pki/ca.crt`
   montato da `pki_data`), poi sostituire il Caddyfile e riavviare.
4. Impostare `MTLS_MODE=required` sul brain e riavviare: senza certificato
   valido gli endpoint agent rispondono 401, con PKI illeggibile 503
   (fail-closed, mai allow).
5. Rollback: `MTLS_MODE=optional` (verifica solo se il cert è presente).

## 3. Backup e restore

Backup automatico ogni 6h (profilo `backup`), retention 7gg, cifrato se
`BACKUP_PASSPHRASE` impostata (altrimenti IN CHIARO con warning esplicito):

```bash
docker compose --profile backup up -d aegis-backup
docker compose exec aegis-backup ls -la /backups
```

Restore MANUALE (doppia conferma):

```bash
I_CONFIRM_RESTORE=yes ./scripts/restore-db.sh /backups/aegis_db_<ts>.sql.gz.enc aegis
# target diverso per prove: ... restore-db.sh <file> aegis_restore_test
```

Ripristino PKI: ricopiare `/app/pki` dal backup prima di firmare.

## 4. Upgrade e rollback

Backend: `docker compose pull/build && up -d` (Alembic `upgrade head`
all'avvio; fallimento = container che non parte, MAI schema parziale).
Rollback: `git checkout <tag-precedente> && up -d --build` (downgrade schema
solo con revisione Alembic dedicata e approvata).

Agent: `POST /deploy/update-command {agent_id, version}` (artefatto firmato
HMAC + manifest Ed25519 quando la pubkey è distribuita). L'agent mette in
stage e applica al restart; ack ok/failed visibile al SOC. Rollback agent:
re-inviare `update-command` con la versione precedente (artefatti versionati
in `ARTIFACT_DIR`, mai sovrascritti).

## 5. Retention purge (manuale, distruttiva)

Default approvati: telemetria 14, alert 90, audit 365, syslog 30 giorni.

```bash
./scripts/purge-retention.sh              # DRY_RUN: solo conteggi
DRY_RUN=0 I_CONFIRM_PURGE=yes ./scripts/purge-retention.sh
```

Eseguire DOPO un backup verificato. Le FK alert→(remediation, threat,
incident, playbook) sono CASCADE/SET NULL: la purge non orfana righe.

## 6. Health quotidiana

- `GET /telemetry/stats`: `active/stale/offline/isolated_agents`,
  `events_duplicated`, `events_seq_gaps` (perdite misurate).
- `GET /telemetry/agents?site=<sito>`: copertura per sito.
- Log container: rotazione 5×10 MB (overlay prod).
- `GET /health/live`: `database`, `redis`, `ollama`, `pipeline`, `pki` e `mtls`.
  `ollama` è opzionale: se non configurato o offline compare come `degraded`,
  ma non rende non pronta la piattaforma core. Database, Redis, pipeline, PKI e
  mTLS restano dipendenze critiche. Usare `/health/ready` per decidere se
  accettare traffico e leggere sempre il dettaglio di ogni check.

## 7. Osservabilità (profilo lab "observability")

- Avvio: `./install.sh lab --observability` (o `.\install.ps1 lab -Observability`).
  Richiede `GRAFANA_ADMIN_PASSWORD` in `.env`; niente montaggi in write oltre i
  volumi interni (Prometheus bind non richiesto).
- Consolle: Prometheus `http://localhost:9090` (scrape `aegis-brain:8000/metrics`
  e `aegis-link:8080/actuator/prometheus`), Grafana `http://localhost:3001`
  (login `admin` + `GRAFANA_ADMIN_PASSWORD`).
- Metriche brain esposte: `aegis_http_requests_total`, `aegis_http_request_seconds`
  (histogram), `aegis_events_*` (ricezione/duplicati/errori per agente),
  `aegis_ingestion_latency_*`, detection latency e queue depth del RedisConsumer.
- **Non previsto in pilot**: in pilot Prometheus/Grafana sono off, le metriche SI
  raccolgono via `scripts/benchmark.py` e `/metrics` del brain (nessun export).

## 8. Aggiornare a runtime non-root (v4.x)

Le immagini aegis-brain girano ora come utente `aegis` (non-root, `USER aegis`
nel Dockerfile). Se si proviene da una versione precedente con volumi
`pki_data`/`artifact_data` root-owned, una sola volta:

```
docker run --rm -u 0 \
  -v aegis-ecosystem_pki_data:/app/pki \
  -v aegis-ecosystem_artifact_data:/app/artifacts \
  --entrypoint sh aegis-ecosystem-aegis-brain:latest \
  -c "chown -R aegis:aegis /app/pki /app/artifacts && chmod 700 /app/pki"
```

Per installazioni nuove non serve nulla: `USER aegis` + dirs create
nell'immagine => i volumi named nascono già aegis-owned.

## 9. Note security/supply chain

- Base Debian (python slim) con CVE HIGH/CRITICAL senza fix upstream: escluse in
  CI via `.trivyignore` (ogni ID è motivato; rimuovere l'ID appena Debian
  rilascia la fix). Tutto il resto resta fail-closed (exit-code 1).
- `apt-get upgrade`/`apk upgrade` eseguiti al build time dei Dockerfile.
- Maven dependency-check in CI richiede `NVD_API_KEY` (fail-closed se assente).
