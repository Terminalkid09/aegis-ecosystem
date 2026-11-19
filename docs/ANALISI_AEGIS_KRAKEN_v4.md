# Aegis + Kraken — Analisi tecnica e roadmap di release

**Data analisi:** 2026-11-08
**Modalità:** sola lettura. Nessun file di codice modificato, nessuna migrazione eseguita, nessun container avviato.
**Ambito verificato:** `aegis-ecosystem` (HEAD `c9831c5`, branch `dev`, 2026-09-21) e `kraken` (HEAD `7fd50a9`, branch `main`, 2026-07-15).

> **Legenda evidenze**
> **[V]** = fatto verificato leggendo codice/config o eseguendo un comando in questa sessione.
> **[D]** = affermato dalla documentazione, non verificato in questa sessione.
> **[I]** = ipotesi ragionata, non provata.
> **[R]** = raccomandazione progettuale.

---

## 1. Decisione finale

Aegis è molto più solido di quanto la sua stessa documentazione lasci intendere: hardening dei default reale, secret fail-closed, immagini pinnate per digest, 572 test realmente verdi. Non è però production-ready, perché 210 test su 787 non sono mai stati eseguiti in questa sessione (dipendono da Postgres/Redis) e manca una licenza.

Kraken è un prototipo funzionante con idee buone (sandbox con `cap_drop: ALL`, `network_mode: none`, honeypot multi-protocollo) ma con difetti che ne impediscono l'uso fuori da un laboratorio isolato: credenziali `changeme` che superano la validazione, Docker socket montato nel container applicativo, e una suite di test che non si colleziona nemmeno.

**Kraken va integrato, ma non fuso.** Diventa un servizio separato nel monorepo, dietro contratto eventi, e non deve mai condividere il processo né il Docker socket con il Brain. L'integrazione appartiene alla **v4.1.0**, ma solo dopo aver chiuso i tre finding bloccanti di Kraken.

---

## 2. Stato di Aegis

### 2.1 Baseline Git [V]

| Voce | Valore |
|---|---|
| Branch attivo | `dev` |
| HEAD | `c9831c53f68dc90bd7cb6bf3703b464100de8332` |
| Data ultimo commit | 2026-09-21 19:11 (+0200) |
| Messaggio | `fix(ci): copy the exact shaded jar into the release, not a glob` |
| Working tree | pulito, unico untracked `.perch/` |
| File tracciati | 489 |
| `.env` tracciato | **no** (solo `.env.example`) |

Il working tree pulito è un buon segnale: nessun lavoro a metà nascosto in stage.

### 2.2 Composizione [V]

| Directory | File | Peso | Ruolo |
|---|---|---|---|
| `aegis-brain` | 609 | 4,8 MB | Backend FastAPI: API, detection, ingest, PKI |
| `aegis-guard` | 228 | 57,4 MB | Agente endpoint Java (ETW, hook) |
| `aegis-link` | 43 | 0,2 MB | Gateway Spring Boot → Redis |
| `NodeTrace` | 165 | 30,1 MB | Agente rete/processi Python |
| `frontend` | 18.833 | 201,8 MB | React 19 + Vite + Tailwind 4 |
| `aegis-ebpf` | 16 | 4,0 MB | Sensore eBPF (C) |

Estensioni dominanti: `.py` 239, `.java` 68, `.yml` 27, `.tsx` 23.

**Nota:** `frontend` pesa 201,8 MB su disco ma è quasi tutto `node_modules`; i file tracciati sono 23 `.tsx` + 13 `.ts`. Il rapporto sorgente/artefatti è sano.

### 2.3 Cosa funziona davvero [V]

**Hardening della configurazione.** `aegis-brain/app/core/config.py:202-232` valida in produzione: `JWT_SECRET` ≥ 32 char, `AGENT_ENROLL_KEY` ≥ 16, `AEGIS_API_KEY` ≥ 32, `MASTER_KEY_B64` che decodifica a esattamente 32 byte, e rifiuta placeholder noti (`change-me`, `replace-with`, `password`, `for_v4.0.0`). Rifiuta anche l'avvio se `ALLOW_OPEN_REGISTRATION` è true fuori dal lab. Questo è il tipo di controllo che quasi nessun progetto open source nella categoria ha.

**Revoca token fail-closed.** `app/core/security.py:156-162`: se Redis non risponde, `is_token_blacklisted` ritorna `True`. Un token potenzialmente revocato viene rifiutato, non accettato. La scelta opposta (fail-open) sarebbe stata più comoda e sbagliata.

**JWT con issuer e audience vincolanti.** `security.py:121-130` verifica `iss="aegis-brain"`, `aud="aegis-api"`, leeway 30s. Impedisce il riuso cross-service di un token.

**Compose con secret obbligatori.** `docker-compose.yml:9,26,77-85` usa la sintassi `${VAR:?messaggio}`: senza `POSTGRES_PASSWORD`, `JWT_SECRET`, `MASTER_KEY_B64` il compose **non parte**. Le immagini sono pinnate per digest SHA256 (`postgres:16-alpine@sha256:cf78e766…`), non per tag mobile. Le porte sono bindate su `127.0.0.1`, non su `0.0.0.0`.

**WebSocket senza token in URL.** `app/api/v1/ws.py:53-57`: il commento spiega che il bearer non va mai nell'URL perché i proxy loggano gli URL, e il codice usa solo il cookie HttpOnly. Corretto.

**Difese zip-bomb in Aegis Total.** `app/api/v1/total.py:224-229`: `PER_ENTRY_MAX_BYTES` 64 MB, `MAX_ANALYZED_MEMBERS` 500, `MAX_NESTED_DEPTH` 2, budget byte decrescente. Più controllo traversal a `:326` e `:872` (`name.startswith("/") or ".." in name`). Non è un `extractall()` ingenuo.

**CSP sul frontend.** `Caddyfile:38`: la dashboard ha una Content-Security-Policy completa (`object-src 'none'`, `frame-ancestors 'none'`). Il commento nel file spiega che senza di essa una XSS nella UI SOC sarebbe la superficie che conta.

**CI con action pinnate per SHA.** `.github/workflows/ci.yml`: tutte le `uses:` sono riferite a commit SHA (`actions/checkout@11d5960a…`), non a tag. Sei job: lint, contract+secret-scan, windows_installers, os_compat, build_and_test, supply_chain, release.

### 2.4 Test realmente eseguiti [V]

```
python -m pytest tests -q --timeout=120
→ 5 failed, 572 passed, 210 skipped, 2 warnings in 198.82s
```

| Esito | Numero | % |
|---|---|---|
| Passed | 572 | 72,7% |
| Skipped | 210 | 26,7% |
| Failed | 5 | 0,6% |

I 5 fallimenti sono **tutti ambientali**, non di codice:
- `test_retention_siem.py` (3 test)
- `test_syslog_listener.py` (2 test)

Causa comune: `ConnectionRefusedError: [WinError 1225]` — nessun Postgres/Redis in ascolto sulla macchina. Il log catturato lo conferma: `Syslog listener attivo su 127.0.0.1:64121` seguito da `Registro sorgente syslog-tcp-… non aggiornato: [WinError 1225]`.

**Questo non significa che Aegis sia verde.** Significa che 572 test passano e 210 non sono stati eseguiti. Un 26,7% di suite non eseguita è un buco di copertura reale, non un dettaglio. `tests/conftest.py:150-155` contiene comunque una guardia encomiabile: rifiuta di partire se `TEST_DATABASE_URL` non sembra un database di test, per non cancellare dati veri.

### 2.5 Detection [V]

| Tipo | Quantità | File |
|---|---|---|
| Sigma YAML | 14 | `app/rules/sigma/rules/*.yml` |
| Correlazione YAML | 5 | `app/rules/correlation/*.yml` |
| Regole statiche Python | 21 | `app/rules/rule_definitions.py:1119` (`STATIC_RULES`) |
| Migrazioni Alembic | 19 | `alembic/versions/0001…0019` |

Il motore Sigma (`app/rules/sigma/engine.py:105-153`) **verifica la logsource**: una regola `product: windows` non gira su un evento Zeek. Il commento a `:3-7` è esplicito sul perché questo conta. È la differenza tra un motore Sigma e un importatore di YAML.

Copertura MITRE: 18 riferimenti tecnica in `app/rules/mitre.py`.

### 2.6 Cosa NON è verificato [D]

Il `README.md` dichiara (righe 215-224) "Brain tests (740+ pytest)", "Guard tests (134 JUnit)", "NodeTrace unit tests", "Frontend: typecheck, build, browser e2e". In questa sessione ho eseguito **solo** la suite Python del Brain. I 134 JUnit di Guard, i test NodeTrace e gli e2e Playwright **non sono stati eseguiti**. Non posso confermarli né smentirli.

---

## 3. Stato di Kraken

### 3.1 Baseline Git [V]

| Voce | Valore |
|---|---|
| Branch | `main` |
| HEAD | `7fd50a942048baa5dfd9999c2064b45c9b9af140` |
| Data | 2026-07-15 16:00 (+0200) |
| Working tree | 2 untracked: `main.js`, `nyx.db` (3,3 MB) |
| CI | `.gitlab-ci.yml` (GitLab, non GitHub) |

Kraken è fermo a luglio, Aegis a settembre: **due mesi di divergenza**. Il file `nyx.db` da 3,3 MB non tracciato suggerisce residui di esecuzione locale.

### 3.2 Architettura [V]

- `app/main.py` — FastAPI, 7,5 KB
- `app/api/v1/endpoints/` — auth, containers, events, export, health, plugins, reports
- `app/services/` — `docker_manager.py` (8,7 KB), `report_pro.py` (33 KB), `attack_service.py`, `geoip.py`, `plugin_manager.py`
- `honeypot/sensors/` — SSH, HTTP, FTP, Telnet
- `monitoring/` — Prometheus, Alertmanager, Grafana
- `nginx/` — TLS, rate limit, security header

### 3.3 Cosa funziona davvero [V]

**Isolamento sandbox.** `docker-compose.yml:26-43` per `kraken_sandbox`: `network_mode: none`, `read_only: true`, `cap_drop: ALL`, `no-new-privileges:true`, `mem_limit: 128m`, `pids_limit: 64`, `cpu_quota: 25000`, tmpfs `noexec,nosuid`. È una configurazione di isolamento seria, non decorativa.

**Estrazione tar con controllo traversal.** `app/services/docker_manager.py:13-35`: `_safe_extract` scarta i membri con path assoluto o `..`, e rinomina ogni file con il suo SHA256. Il nome scelto dal malware non tocca mai il filesystem.

**nginx con rate limit e header.** `nginx/nginx.conf`: zone `login` a 10r/m, `export` a 30r/m, `client_max_body_size 64k`, HSTS, `server_tokens off`, `/metrics` ristretto a range privati.

**Prometheus/Alertmanager/Grafana non pubblicati.** Usano `expose:`, non `ports:` — raggiungibili solo sulla rete interna `kraken_internal`. (Avevo inizialmente sospettato il contrario; il codice dice `expose`. Corretto così.)

### 3.4 Test [V] — non eseguibili

```
python -m pytest tests -q
→ ImportError: cannot import name 'jwt' from 'jose'
```

La suite **non si colleziona**. `app/core/security.py:5` fa `from jose import JWTError, jwt`, ma il pacchetto `jose` installato in questo ambiente è un'installazione parziale (contiene `jwe.py`, `jwk.py`, `constants.py`, `exceptions.py` — manca `jwt.py`).

Questo è in parte un problema d'ambiente, ma il punto strutturale resta: **Kraken dipende da `python-jose`**, la libreria che Aegis ha deliberatamente rimosso. Il commento in `aegis-brain/requirements.txt` lo dice esplicitamente: *"python-jose rimosso — API rotta + CVE senza fix"*.

**Nessun test di Kraken è stato eseguito. Non dichiaro nulla sul suo stato di salute.**

---

## 4. Architettura e flussi

### 4.1 Flusso agente (Aegis) [V]

```
enrollment → auth (agent_id+secret) → telemetria → dedup → persistenza
→ detection (21 statiche + 14 Sigma) → correlazione (5) → alert → enrichment → incidente
```

Punti verificati:
- `app/core/agent_deps.py:9-29` — validazione `agent_id` + secret, 401 su formato invalido.
- `app/core/agent_deps.py:34-41` — controllo `RevokedCert`. **Qui c'è un fail-open**: se la query sulla tabella `RevokedCert` solleva un'eccezione, il codice fa `pass` e prosegue ai controlli file/mTLS. Il commento lo ammette ("fail-open qui, fail-closed lì"). È una scelta difendibile ma va documentata come tale, non nascosta in un commento.
- `app/services/event_dedup.py` + `DEDUP_TTL_SECONDS: 86400` — dedup per `event_id`.
- `app/core/config.py:165` — `APP_EVENTS_PER_MIN: 10000` come ceiling anti-flood.

### 4.2 Flusso risposta [V]

```
alert → playbook → autorizzazione → dispatch comando → agente → audit
```

`app/services/playbook_engine.py:200-339` implementa: `webhook`, `block_ip`, `kill_process`, `block_ip_temporal`, `isolate_host`, `update_agent`, `script`, `quarantine_binary`, `remove_persistence`, `verify`, `dns_sinkhole`, `collect_ioc`.

Le azioni verso l'endpoint passano per `_send_agent_command` — comandi **nominati** con parametri strutturati. Non c'è una shell generica nel percorso di response. Questo è esattamente il modello che il prompt richiede.

`dns_sinkhole` (`:325-330`) manda `{"command": "DNS_SINKHOLE", "domain": target}` all'agente. **Non esiste TTL, non esiste approvazione, non esiste rollback** in questo punto. Vedi §10.

### 4.3 Flusso deployment [V]

`app/api/v1/deploy.py`:
- `:445-467` — `artifact_name_for`, `sha256_file`; la firma OTA è il manifest Ed25519.
- `:508-530` — `sign_manifest_bundle`, manifest firmato.
- `:556-561` — download artefatto con `Path(name).name` come anti-traversal (solo basename).
- `:50-57` — chiave HMAC di approvazione derivata da `JWT_SECRET`, con fallback `"aegis-approval-dev-only"`.

Il modello "l'agente verifica sha256 + HMAC prima di eseguire" è corretto e ben implementato.

### 4.4 Flusso honeypot (Kraken) [V]

```
attaccante → SSH sensor (2222) → sessione → comando
→ POST /containers/exec → docker exec sh -c <comando> → sandbox → output
→ diff container → cattura malware → destroy
```

`honeypot/sensors/ssh_sensor.py:134-144`: la riga digitata dall'attaccante (`cmd = line.strip()`) viene passata a `_sandbox_exec(session_id, cmd)`, che fa `POST /containers/exec?cmd=...`, che arriva a `docker_manager.exec_command`, che esegue `c.exec_run(["sh", "-c", cmd])` (`docker_manager.py:148`).

Il flusso è **by design**: un honeypot deve eseguire i comandi dell'attaccante per raccogliere IoC. La domanda di sicurezza non è "perché c'è `sh -c`", ma "quanto è solida la gabbia". Vedi §5.

---

## 5. Finding di sicurezza

### AEGIS-SEC-001 — Esecuzione binaria arbitraria via playbook `script`

```text
ID: AEGIS-SEC-001
Titolo: Playbook action "script" esegue un processo arbitrario sul server Brain
Severità: Medium
Confidence: Alta
Componente: aegis-brain/app/services/playbook_engine.py:276-297
Precondizioni: PLAYBOOK_SCRIPT_ENABLED=true; ruolo admin; capacità di creare/modificare un playbook
Evidenza: subprocess.run(target.split(), capture_output=True, text=True,
         timeout=min(int(params.get("timeout", 30)), 120))
Impatto: esecuzione di un binario arbitrario con i privilegi del processo Brain.
         Non è shell injection (nessuna shell, nessun shell=True), ma è esecuzione
         di processo arbitrario: `target` è una stringa libera splittata su spazi.
Riproduzione: creare un playbook con action_type="script", target="/bin/sh -c id",
              con flag attivo e ruolo admin.
Fix consigliato: sostituire `target.split()` con un'allowlist di binari
                 (path assoluti, no argomenti arbitrari) oppure eliminare
                 l'azione in favore di comandi nominati verso l'agente.
Test di regressione: test che con PLAYBOOK_SCRIPT_ENABLED=true e target non in
                     allowlist l'azione ritorni {"status": "blocked"}.
Release target: v4.3.0 (rimozione), guardia in v4.1.0
```

**Attenuanti verificate:** il gate è doppio. `app/api/v1/playbooks.py:76-81` blocca la creazione se il flag è off o il ruolo non è admin; `playbook_engine.py:281-283` ricontrolla il flag a runtime, con il commento esplicito "difesa in profondità: righe scritte prima del flag o a mano nel DB". Default `PLAYBOOK_SCRIPT_ENABLED: False` (`config.py:113`). Il rischio residuo è reale ma confinato a un deployment che ha attivato esplicitamente la feature.

### AEGIS-SEC-002 — Fallback silenzioso della chiave HMAC di approvazione

```text
ID: AEGIS-SEC-002
Titolo: La chiave HMAC delle approvazioni degrada a un valore noto se JWT_SECRET manca
Severità: Low
Confidence: Alta
Componente: aegis-brain/app/api/v1/deploy.py:50-52
Precondizioni: JWT_SECRET non impostato (possibile solo con DEBUG=true)
Evidenza: _APPROVAL_HMAC_KEY = hashlib.sha256(
             (settings.JWT_SECRET or "aegis-approval-dev-only").encode()).digest()
Impatto: con la chiave nota, un PIN di approvazione a 6 cifre diventa forgiabile
         offline. Il binding su (kind, job_id, ip) limita il riuso ma non la forgiatura.
Riproduzione: avviare con DEBUG=true e JWT_SECRET assente, generare un MAC con la
              stringa "aegis-approval-dev-only".
Fix consigliato: rifiutare l'avvio se JWT_SECRET manca anche in DEBUG, oppure
                 generare una chiave casuale per processo e invalidare le
                 approvazioni al restart.
Test di regressione: test che con JWT_SECRET assente la derivazione sollevi.
Release target: v4.1.0
```

### AEGIS-SEC-003 — Fail-open sul controllo di revoca certificato agente

```text
ID: AEGIS-SEC-003
Titolo: Un errore DB sul controllo RevokedCert lascia proseguire l'agente
Severità: Medium
Confidence: Alta
Componente: aegis-brain/app/core/agent_deps.py:34-41
Precondizioni: errore transitorio su Postgres durante la query RevokedCert
Evidenza: except ...: pass  # tabella assente o errore transitorio:
         lascia passare al check file/mTLS (fail-open qui, fail-closed lì)
Impatto: un agente revocato può inviare telemetria durante una finestra di
         errore DB, se il controllo file/mTLS non lo intercetta.
Riproduzione: revocare un agente, poi far fallire la query RevokedCert
              (es. tabella temporaneamente non raggiungibile).
Fix consigliato: negare (401) su eccezione, coerentemente con la scelta
                 fail-closed già adottata per la blacklist JWT in security.py:156-162.
Test di regressione: mock che solleva sulla query RevokedCert → atteso 401.
Release target: v4.1.0
```

### AEGIS-SEC-004 — Nessun file LICENSE nel repository

```text
ID: AEGIS-SEC-004
Titolo: Assenza di licenza: il progetto non è legalmente adottabile
Severità: High (per il prodotto, non per la sicurezza tecnica)
Confidence: Alta
Componente: radice del repository
Evidenza: nessun file LICENSE/LICENSE.md/LICENSE.txt alla radice; gli unici
          LICENSE trovati sono dentro NodeTrace/agents/python/dist/... e
          appartengono a dipendenze di terze parti (cryptography).
Impatto: senza licenza esplicita il default legale è "tutti i diritti riservati".
         Nessuna azienda può adottarlo, nessun contributore sa cosa cede.
         È il singolo blocco più grande all'adozione open source.
Riproduzione: n/a
Fix consigliato: scegliere e committare una licenza (Apache-2.0 se l'obiettivo
                 è adozione aziendale con protezione brevetti; AGPL-3.0 se
                 l'obiettivo è impedire il SaaS concorrente).
Test di regressione: check in CI che fallisca se LICENSE manca.
Release target: v4.1.0 — bloccante
```

### KRAKEN-SEC-001 — Credenziali `changeme` che superano la validazione

```text
ID: KRAKEN-SEC-001
Titolo: I default di Kraken passano il controllo di lunghezza e avviano in produzione
Severità: High
Confidence: Alta
Componente: kraken/app/core/config.py:76-93; kraken/.env.example:9-10;
             kraken/docker-compose.yml:57-58
Precondizioni: deploy che usa .env.example o i fallback del compose
Evidenza: config.py:78  if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
         .env.example:9  SECRET_KEY=changeme_super_secret_key_please_change_min_32_chars
         compose:57      SECRET_KEY=${SECRET_KEY:-changeme_super_secret_key_please_change}
         La stringa "changeme_super_secret_key_please_change_min_32_chars" è lunga
         49 caratteri: supera il test `len < 32` e il processo parte.
Impatto: SECRET_KEY noto pubblicamente → forgiatura di JWT admin.
         INTERNAL_API_KEY noto → accesso a /containers/exec con esecuzione comandi.
Riproduzione: docker compose up con .env.example non modificato; firmare un JWT
              con la chiave pubblica del repository.
Fix consigliato: replicare il validatore di Aegis (config.py:218-222) che rifiuta
                 i marker "change-me"/"changeme"/"replace-with"; usare ${VAR:?}
                 nel compose invece dei fallback.
Test di regressione: test che con SECRET_KEY contenente "changeme" l'avvio fallisca.
Release target: v4.1.0 — bloccante
```

### KRAKEN-SEC-002 — Docker socket nel container applicativo

```text
ID: KRAKEN-SEC-002
Titolo: /var/run/docker.sock montato in kraken_app: montaggio :ro non è una difesa
Severità: High
Confidence: Alta
Componente: kraken/docker-compose.yml:65
Precondizioni: accesso al container kraken_app (RCE, SSRF, o credenziale interna)
Evidenza: - /var/run/docker.sock:/var/run/docker.sock:ro
Impatto: il flag :ro limita le scritture sul file socket, non le chiamate all'API
         Docker. Chi controlla il socket controlla il demone: può creare un
         container privilegiato con --pid=host e montare il filesystem host.
         Equivale a root sull'host.
Riproduzione: da dentro kraken_app, `docker run -v /:/host --privileged alpine chroot /host`
Fix consigliato: rimuovere il mount. Esporre un demone Docker dedicato su socket
                 TCP con ACL, oppure usare un socket proxy che consenta solo
                 container create/start/stop/rm sui label kraken.managed=true.
Test di regressione: test di configurazione che verifichi l'assenza del mount
                     nel compose di produzione.
Release target: v4.1.0 — bloccante
```

### KRAKEN-SEC-003 — Input dell'attaccante in `sh -c` dentro la sandbox

```text
ID: KRAKEN-SEC-003
Titolo: I comandi SSH dell'attaccante raggiungono `sh -c` nel container sandbox
Severità: Medium
Confidence: Alta
Componente: honeypot/sensors/ssh_sensor.py:134-144 →
             app/api/v1/endpoints/containers.py:76-86 →
             app/services/docker_manager.py:142-154
Precondizioni: connettività al sensore SSH (porta 2222 pubblicata su 0.0.0.0)
Evidenza: ssh_sensor.py:144  output = await _sandbox_exec(session_id, cmd)
         docker_manager.py:148  res = c.exec_run(["sh", "-c", cmd])
         containers.py:79  cmd: str = Query(..., max_length=512)
Impatto: esecuzione arbitraria DENTRO la sandbox. Contenuta da cap_drop ALL,
         network_mode none, read_only, no-new-privileges, pids_limit 64.
         Il rischio residuo è una fuga dalla sandbox (kernel exploit) o
         esaurimento risorse dell'host.
Riproduzione: ssh -p 2222 qualsiasi@host, poi digitare `id; cat /etc/passwd`.
Fix consigliato: mantenere il comportamento (è la funzione del honeypot) ma
                 (a) bindare le porte dei sensori su un'interfaccia dedicata,
                 (b) aggiungere un timeout per comando,
                 (c) registrare ogni comando come evidenza con timestamp.
Test di regressione: test che un comando oltre 512 char sia rifiutato (già
                     presente via max_length) e che la sandbox venga distrutta
                     anche in caso di eccezione.
Release target: v4.2.0
```

### KRAKEN-SEC-004 — `python-jose` con CVE senza fix

```text
ID: KRAKEN-SEC-004
Titolo: Kraken dipende da python-jose, rimosso da Aegis per CVE e API rotta
Severità: High
Confidence: Alta
Componente: kraken/requirements.txt:12; kraken/app/core/security.py:5;
             kraken/app/api/v1/endpoints/containers.py:3
Precondizioni: deploy di Kraken
Evidenza: requirements.txt:12  python-jose[cryptography]==3.3.0
         security.py:5  from jose import JWTError, jwt
         aegis-brain/requirements.txt (commento): "python-jose rimosso —
         API rotta + CVE senza fix"
         In questa sessione: ImportError: cannot import name 'jwt' from 'jose'
Impatto: dipendenza non mantenuta con vulnerabilità note; in questo ambiente
         la suite di test non si colleziona nemmeno.
Riproduzione: python -m pytest tests -q → ImportError
Fix consigliato: migrare a PyJWT come ha fatto Aegis. Il codice usa solo
                 encode/decode/get_unverified_header: la migrazione è meccanica.
Test di regressione: la suite deve tornare a collezionarsi.
Release target: v4.1.0 — bloccante
```

### KRAKEN-SEC-005 — Decodifica JWT senza verifica di scadenza nel percorso admin

```text
ID: KRAKEN-SEC-005
Titolo: _get_admin_or_internal decodifica con verify_exp=False per estrarre il jti
Severità: Low
Confidence: Alta
Componente: kraken/app/api/v1/endpoints/containers.py:37
Precondizioni: token scaduto ma non in blacklist
Evidenza: payload = _jwt.decode(token, settings.SECRET_KEY,
             algorithms=[settings.JWT_ALGORITHM], options={"verify_exp": False})
Impatto: la decodifica serve solo a leggere il jti per la blacklist, e subito dopo
         decode_access_token() rivalida con verify_exp=True. L'impatto è quindi
         limitato, ma il pattern è fragile: se qualcuno in futuro usasse `payload`
         per autorizzare, la scadenza sarebbe ignorata.
Riproduzione: n/a (nessuna escalation dimostrata)
Fix consigliato: usare jwt.decode con verify_exp=True e gestire l'eccezione
                 separatamente per la blacklist.
Test di regressione: token scaduto → 403.
Release target: v4.2.0
```

### KRAKEN-SEC-006 — Grafana con password admin di default

```text
ID: KRAKEN-SEC-006
Titolo: Grafana parte con admin/admin se GRAFANA_PASSWORD non è impostata
Severità: Medium
Confidence: Alta
Componente: kraken/docker-compose.yml:202
Precondizioni: deploy senza GRAFANA_PASSWORD
Evidenza: GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
Impatto: accesso admin a Grafana. Il servizio è su `expose:` (rete interna),
         quindi serve un pivot per raggiungerlo — ma un pivot è esattamente
         ciò che un attaccante cerca dopo KRAKEN-SEC-002.
Riproduzione: n/a senza accesso alla rete interna
Fix consigliato: ${GRAFANA_PASSWORD:?GRAFANA_PASSWORD must be set}
Test di regressione: check di configurazione.
Release target: v4.1.0
```

### Riepilogo finding

| ID | Severità | Bloccante release | Release |
|---|---|---|---|
| AEGIS-SEC-001 | Medium | no | v4.3.0 |
| AEGIS-SEC-002 | Low | no | v4.1.0 |
| AEGIS-SEC-003 | Medium | no | v4.1.0 |
| AEGIS-SEC-004 | High (prodotto) | **sì** | v4.1.0 |
| KRAKEN-SEC-001 | High | **sì** | v4.1.0 |
| KRAKEN-SEC-002 | High | **sì** | v4.1.0 |
| KRAKEN-SEC-003 | Medium | no | v4.2.0 |
| KRAKEN-SEC-004 | High | **sì** | v4.1.0 |
| KRAKEN-SEC-005 | Low | no | v4.2.0 |
| KRAKEN-SEC-006 | Medium | no | v4.1.0 |

---

## 6. Bug logici e affidabilità

### AEGIS-REL-001 — 210 test mai eseguiti in questa sessione

**[V]** 26,7% della suite dipende da Postgres/Redis e viene skippata. La CI (`build_and_test`) presumibilmente li esegue con i service container, ma in locale no. Il rischio è che un test rotto resti verde in CI perché marcato skip anche lì. **Non ho verificato** se la CI li esegua davvero: non ho eseguito la pipeline.

### AEGIS-REL-002 — Directory malformata `aegis-brain/app;C`

**[V]** Esiste una directory `aegis-brain\app;C` vuota, non tracciata da git, residuo di un path-join errato su Windows. Non è un bug di codice ma è sporcizia che confonde chi esplora il repo. Va cancellata (non l'ho fatto: modalità sola lettura).

### AEGIS-REL-003 — `redis_client` creato all'import del modulo

**[V]** `app/core/security.py:24`: `redis_client = redis.from_url(...)` a livello di modulo. Se `REDIS_URL` è malformato, l'errore emerge all'import e non al primo uso, rendendo il messaggio di errore meno chiaro. Non è un bug funzionale, è un problema di diagnostica.

### KRAKEN-REL-001 — Suite di test non collezionabile

**[V]** `ImportError` su `jose`. Vedi KRAKEN-SEC-004. Finché non si migra a PyJWT, **zero** copertura verificabile.

### KRAKEN-REL-002 — `read_only=False` nel container sandbox creato via API

**[V]** `docker_manager.py:128`: `read_only=False` esplicito nella chiamata `containers.run`, mentre il compose dichiara `read_only: true` per il servizio `kraken_sandbox`. Sono due percorsi diversi: il compose descrive il servizio, ma i container vengono creati **a runtime** dal manager con `read_only=False`. La difesa del compose non si applica ai container effettivi. Questo è un disallineamento reale tra configurazione dichiarata e comportamento.

### KRAKEN-REL-003 — `_safe_extract` non ha limiti di dimensione

**[V]** `docker_manager.py:13-35`: `content = f.read()` legge l'intero membro in memoria senza cap. Un tar bomb (membro da GB) esaurisce la RAM del container `kraken_app`. Il compose non impone `mem_limit` su `kraken_app`. Il controllo traversal c'è, il controllo dimensione no.

### KRAKEN-REL-004 — `_active` dict non ripulito su crash del watchdog

**[V]** `docker_manager.py:55,70,81`: `self._active[session_id]` viene popolato e rimosso in `destroy_sandbox`. Se il processo muore, i container restano orfani: nessun reconcile all'avvio. Con `SANDBOX_MAX_CONCURRENT: 20`, venti orfani bloccano il servizio in modo permanente.

---

## 7. Deployment e supply chain

### Aegis [V] — solido

| Controllo | Stato | Evidenza |
|---|---|---|
| Immagini pinnate per digest | sì | `docker-compose.yml:3,21,38,160,182` |
| Secret obbligatori | sì | `${VAR:?}` su 6 variabili |
| Bind su loopback | sì | `127.0.0.1:` su postgres, redis, brain, link, frontend |
| Healthcheck con dipendenze | sì | `condition: service_healthy` |
| Action CI pinnate per SHA | sì | tutte le `uses:` |
| Job supply chain | sì | `supply_chain` + SBOM (`sbom.cyclonedx.json`) |
| `.env` non tracciato | sì | gitignore + verifica `git ls-files` |
| CSP sul frontend | sì | `Caddyfile:38` |
| Licenza | **no** | AEGIS-SEC-004 |

### Kraken [V] — fragile

| Controllo | Stato | Evidenza |
|---|---|---|
| Immagini pinnate per digest | **no** | `postgres:15-alpine`, `redis:7-alpine`, `grafana/grafana:10.4.0` |
| Secret obbligatori | **no** | fallback `changeme_*` |
| Docker socket | **sì, esposto** | `:65` |
| Porte sensori su 0.0.0.0 | **sì** | `2222:2222`, `8080:8080`, `2121:2121`, `2323:2323` |
| TLS | parziale | nginx con cert placeholder `/etc/nginx/ssl/cert.pem` |
| CI | GitLab | `.gitlab-ci.yml`, non verificato |
| Licenza | sì | `LICENSE` presente |

**Nota sulle porte sensori:** `"2222:2222"` senza prefisso IP significa `0.0.0.0`. Per un honeypot è intenzionale (deve essere raggiungibile), ma va dichiarato esplicitamente nella documentazione, perché su un host cloud significa esposizione a Internet.

---

## 8. Detection e Sigma

### Stato [V]

14 regole Sigma, 5 di correlazione, 21 statiche. Copertura per prodotto: Windows (7), Linux (2), Zeek (2), Suricata (1), proxy (1), firewall (1).

### Qualità — cosa è fatto bene

Il motore verifica la logsource (`engine.py:105-153`) con mappe esplicite `_PRODUCT_SOURCES`, `_WINDOWS_CATEGORY_TYPES`, `_WINDOWS_SERVICE_HINTS`, `_NETWORK_SERVICE_HINTS`. Una regola `category: process_creation` su Windows accetta solo `event_type in {"process_creation"}`. Questo evita la valanga di falsi positivi tipica degli importatori ingenui.

`evaluate()` (`:155-177`) isola ogni regola in un try/except: una regola che solleva non ferma la pipeline. Corretto per robustezza, ma **nasconde gli errori**: una regola rotta viene saltata in silenzio per sempre. Manca un contatore di errori per regola.

### Lacune

**Copertura MITRE insufficiente.** 18 riferimenti tecnica per 14 regole Sigma + 21 statiche. Le tecniche coperte sono concentrate su execution e persistence. Non ho trovato regole per: credential access (T1003), lateral movement (T1021), C2 beaconing (T1071), defense evasion via LOLBins (T1218), exfiltration (T1041).

**Nessuna regola su process tree.** Esiste `SUSPICIOUS_PARENT_CHILD` (`rule_definitions.py:253`) come tabella, ma non è chiaro quante regole la usino. Non verificato in dettaglio.

**Nessun test negativo per regola.** `tests/test_detection_rules.py` è 36 KB — sostanzioso — ma non ho verificato che ogni regola abbia sia un caso positivo sia un caso negativo.

### Catalogo proposto [R]

Priorità per v4.1.0 (DNS/process/network, come richiesto):
1. `dns_query` con dominio raro (entropia + assenza in cache) — richiede storico DNS
2. `dns_query` con lunghezza > 100 char (tunneling) — **esiste già** (`zeek_dns_long_query_tunneling.yml`)
3. `process_creation` con parent in `{winword, excel, outlook, acrord32}` e figlio in `{powershell, cmd, wscript, mshta}`
4. `process_creation` da directory scrivibile utente — **esiste già** (`win_process_from_user_writable_dir.yml`)
5. `network_connect` verso IP con ASN hosting e porta non standard, correlato a processo non browser
6. Beaconing: intervallo regolare verso stesso dominio (esiste `CORR_BEACON_*` in config, manca la regola)

Per v4.2.0: LOLBins (`certutil -urlcache`, `bitsadmin /transfer`, `regsvr32 /i:http`), credential access (accesso a `lsass.exe` da processo non firmato), scheduled task con path sospetto.

Per ogni regola: telemetria richiesta, falsi positivi attesi, caso positivo e negativo nel corpus. `tests/corpus/` ha già la struttura a tre split (training/validation/regression) — va sfruttata.

---

## 9. File / ZIP / log / sandbox analysis

### Cosa esiste già in Aegis [V]

`app/api/v1/total.py` (76 KB) implementa analisi statica: identificazione formato, entropia, estrazione stringhe, IoC regex, parsing PE (sezioni, overlay, import), analisi OOXML, analisi ZIP annidata.

Difese verificate (`:224-229`, `:326`, `:854-872`):
- `PER_ENTRY_MAX_BYTES = 64 MB`
- `MAX_ANALYZED_MEMBERS = 500`
- `MAX_NESTED_DEPTH = 2`
- `MAX_TEXT_SCAN_BYTES = 5 MB`, `MAX_UTF16_SCAN_BYTES = 16 MB`
- budget byte decrescente (`budget = max_bytes`, poi sottratto per membro)
- rifiuto path assoluti e `..`
- troncamento dichiarato (`"truncated": True`), non silenzioso

`app/services/yara_engine.py` + `app/api/v1/yara.py` + migrazione `0015_yara_rules.py`: supporto YARA.
`app/services/disasm.py` (17 KB): disassembler PE con capstone, fail-soft.

### Cosa manca [V]

**Nessuna sandbox dinamica in Aegis.** Non ho trovato esecuzione di campioni. `TOTAL_MAX_FILE_MB`, `TOTAL_RETENTION_DAYS` esistono come config ma il percorso è statico.

**Nessun PCAP.** Nessun riferimento a `scapy`, `dpkt`, `pyshark` in `requirements.txt`.

**Nessuna chain of custody.** I risultati non sono firmati. La firma Ed25519 copre gli artefatti di deploy, non i risultati di analisi.

### Proposta [R]

```
upload → quarantine → hash(SHA256) → type detection → limit check
→ static (già presente) → sandbox job (Kraken) → IOC extraction
→ enrichment (OSINT già presente) → Sigma candidate → approvazione → enforcement
```

Il punto chiave: **la sandbox è l'unica cosa che Kraken porta che Aegis non ha.** Questo è il vero argomento a favore dell'integrazione, più di qualsiasi considerazione architetturale.

Requisiti non negoziabili per il percorso file:
- quarantena su volume separato, mai eseguibile
- hash calcolato **prima** di qualsiasi parsing
- limite dimensione prima della decompressione (non dopo)
- timeout per job sandbox
- retention esplicita e cancellazione verificata
- risultato firmato con HMAC e legato a `evidence_id`
- audit di ogni accesso al campione

---

## 10. DNS e firewall policy engine

### Cosa esiste [V]

`playbook_engine.py:325-330` — `dns_sinkhole`: manda `{"command": "DNS_SINKHOLE", "domain": target}` all'agente.
`playbook_engine.py:219-224` — `block_ip`: `{"command": "BLOCK_IP", "ip": target}`.
`playbook_engine.py:237-243` — `block_ip_temporal`: include `duration_seconds` (default 3600).

**Solo `block_ip_temporal` ha un TTL.** `dns_sinkhole` e `block_ip` sono permanenti e senza rollback. Non c'è approvazione, non c'è scope, non c'è conflitto tra regole, non c'è dry-run.

### Proposta [R]

Il motore deve essere **policy-first, non action-first**. La differenza: oggi un playbook *esegue* un blocco; domani un motore *propone* una policy che qualcuno approva.

```
evidenza (alert + IoC) → candidate policy
  { type: dns_deny | ip_block | fw_rule,
    target, scope (endpoint|network|fleet),
    ttl_s, confidence, evidence_id, rationale }
→ conflict check (target già in allowlist? IP condiviso/CDN?)
→ dry-run (mostra cosa cambierebbe, senza applicare)
→ approvazione umana (ruolo analyst+, con MAC legato a job+IP)
→ apply con TTL
→ audit
→ auto-rollback alla scadenza
```

Regole di sicurezza non negoziabili:
1. **Nessun blocco permanente senza approvazione esplicita.** Il default è TTL.
2. **Protezione CDN/IP condivisi.** Bloccare un IP Cloudflare blocca mezzo Internet. Serve una denylist di range condivisi che forza `scope=endpoint` invece di `scope=fleet`.
3. **Safe mode.** Se una policy colpirebbe più del N% degli asset, richiede approvazione a due persone.
4. **Rollback sempre disponibile**, con lo stato precedente salvato.
5. **L'LLM può suggerire, mai applicare.** Il modello propone la policy con rationale e `evidence_id`; l'applicazione passa dal gate di approvazione.

Questo appartiene alla **v4.3.0**, non prima: richiede il contratto eventi e l'audit unificato della v4.1.0 come prerequisito.

---

## 11. Decisione sull'integrazione di Kraken

### Confronto delle quattro opzioni

**Opzione A — Kraken separato.**
Pro: zero rischio di contaminazione, indipendenza di release. Contro: due deployment, due stack di autenticazione, due audit log, due backup, due documentazioni. Per un utente significa installare due prodotti e collegarli a mano. È lo stato attuale, e lo stato attuale non funziona: due mesi di divergenza e zero integrazione.

**Opzione B — Kraken nel monorepo come servizio separato.**
Pro: un solo `docker compose up`, un solo contratto eventi, una sola CI, versioning coordinato, un solo audit log. Contro: richiede disciplina sui confini (Kraken non deve importare codice del Brain). È l'opzione che il prompt indica come default da verificare.

**Opzione C — Kraken assorbito nel Brain.**
Pro: nessun salto di rete. Contro: **inaccettabile**. Il Brain gestisce autenticazione, PKI e audit; Kraken esegue codice arbitrario di attaccanti e ha bisogno del Docker socket. Fondere i due significa che una fuga dalla sandbox honeypot dà accesso diretto al sistema che custodisce le chiavi. Il blast radius passa da "un container compromesso" a "l'intera piattaforma". Da escludere senza appello.

**Opzione D — Kraken microservizio autonomo nell'ecosistema.**
Pro: confini massimi. Contro: è l'Opzione B con più cerimonia. La differenza tra "servizio nel monorepo" e "microservizio autonomo" è reale solo se c'è un team separato che lo possiede. Oggi non c'è.

### Raccomandazione

**Opzione B.** Kraken entra nel monorepo come `kraken/`, servizio separato, con:
- proprio container, propria rete, **proprio Docker socket** (mai condiviso col Brain)
- comunicazione verso il Brain **solo** via HTTP autenticato con contratto eventi versionato
- nessun import di codice condiviso oltre agli schemi Pydantic del contratto
- CI unificata ma job separati

Il confine: **Kraken produce eventi, il Brain li consuma e decide.** Kraken non deve mai poter leggere alert, playbook o credenziali del Brain. La direzione del flusso è a senso unico.

---

## 12. Architettura target

```
                    ┌─────────────────────────────┐
   endpoint ───────▶│  aegis-guard (Java)         │──┐
                    │  NodeTrace (Python)         │  │ telemetria firmata
                    └─────────────────────────────┘  │
                                                     ▼
   log/firewall ───▶ aegis-link (Spring) ──────▶ Redis Streams
   syslog/zeek   ───▶ ingest parsers ──────────▶     │
                                                     ▼
                    ┌──────────────────────────────────────────┐
                    │  aegis-brain (FastAPI)                   │
                    │  auth · detection · correlation · SOAR   │
                    │  PKI · audit · deploy · policy engine    │
                    └──────────────────────────────────────────┘
                                    ▲
                                    │ contratto eventi (HTTP + HMAC)
                                    │ senso unico: Kraken → Brain
                    ┌───────────────┴──────────────────────────┐
                    │  kraken (servizio separato)              │
                    │  honeypot · sandbox · malware capture    │
                    │  PROPRIO docker socket · propria rete    │
                    └──────────────────────────────────────────┘
```

Regole di confine:
1. Kraken non legge mai dal database del Brain.
2. Kraken non condivide il Docker socket con nessuno.
3. Il Brain non esegue mai codice non fidato.
4. Ogni evento Kraken ha `event_id`, `source`, `sensor_id`, `schema_version`, `evidence_id`.
5. Il Brain può rifiutare un evento Kraken malformato senza perdere il resto del batch.

---

## 13. Decisione su Kafka, Kubernetes e object storage

**Redis Streams: sì, ora.** [R] Aegis ha già Redis in produzione per blacklist, dedup, rate limit. Redis Streams aggiunge consumer group e ack senza un nuovo componente. Per il volume attuale (ceiling 10.000 eventi/min per agente) è più che sufficiente.

**Kafka/Redpanda: no, non prima della v5.0.** [R] Soglia quantitativa per prenderlo in considerazione: **> 50.000 eventi/s sostenuti** oppure **> 20 consumer group indipendenti** oppure necessità di replay storico su finestre > 7 giorni. Sotto queste soglie Kafka è costo operativo puro: un cluster da gestire, monitorare, aggiornare, con un team che oggi non esiste.

**Kubernetes: no, non prima della v5.0.** [R] Soglia: **> 5 nodi** o necessità di autoscaling su carico variabile o multi-tenant con isolamento forte. Il compose attuale copre developer laptop, home lab, single-server pilot e small business. Per il multi-node aziendale, la v5.0 può valutare K8s — ma solo dopo che il compose è stato provato in produzione reale su un singolo server.

**Object storage: sì, in forma minima, in v4.2.0.** [R] I campioni malware e gli artefatti di analisi non appartengono a un volume Docker. Serve uno storage con retention, immutabilità e cancellazione verificata. Garage in locale, S3 in cloud. Non un data lake: un bucket con policy.

**Il principio:** ogni componente aggiunto deve risolvere un problema misurato, non anticipato. Oggi il problema misurato è "non c'è integrazione tra due progetti", non "non scaliamo".

---

## 14. Roadmap release

### v4.1.0 — Consolidamento e integrazione minima

| Item | Valore | Costo | Rischio | Bloccante |
|---|---|---|---|---|
| LICENSE (AEGIS-SEC-004) | Alto | Basso | Nullo | **sì** |
| Kraken: secret senza `changeme` (KRAKEN-SEC-001) | Alto | Basso | Basso | **sì** |
| Kraken: rimozione Docker socket (KRAKEN-SEC-002) | Alto | Medio | Medio | **sì** |
| Kraken: migrazione PyJWT (KRAKEN-SEC-004) | Alto | Basso | Basso | **sì** |
| Aegis: fail-closed su RevokedCert (AEGIS-SEC-003) | Medio | Basso | Basso | no |
| Aegis: rimozione fallback HMAC (AEGIS-SEC-002) | Basso | Basso | Nullo | no |
| Contratto eventi v1 (schema + versione) | Alto | Medio | Basso | no |
| Kraken come servizio nel monorepo | Alto | Medio | Medio | no |
| Ingestione Kraken → Brain | Alto | Medio | Medio | no |
| Audit unificato | Medio | Medio | Basso | no |
| Test end-to-end Kraken → Brain | Alto | Medio | Basso | no |
| Deployment riproducibile (compose unico) | Alto | Basso | Basso | no |
| 5 regole Sigma DNS/process/network | Medio | Basso | Basso | no |

**Criterio di completamento:** `docker compose up` da zero su una macchina pulita produce uno stack funzionante; un evento honeypot appare come alert nel Brain entro 5 secondi; la suite Kraken si colleziona ed esegue.

### v4.2.0 — Deception e file intelligence

- Analisi file/ZIP con sandbox Kraken come job asincrono
- Estrazione IoC e generazione candidati Sigma
- Gestione campioni malware con retention e cancellazione verificata
- Object storage minimo (S3-compatibile)
- Process tree e DNS history nella dashboard
- Dashboard integrata
- KRAKEN-SEC-003 (timeout comando), KRAKEN-SEC-005, KRAKEN-REL-002/003/004

### v4.3.0 — Response intelligence

- DNS policy engine con TTL, dry-run, approvazione, rollback
- Firewall policy engine con protezione CDN/IP condivisi
- Playbook nominati con approvazione a due livelli per azioni distruttive
- **Rimozione dell'azione `script`** (AEGIS-SEC-001)
- Enforcement su agenti con verifica del risultato

### v5.0.0 — Scalabilità (solo se giustificata)

Kafka/Redpanda, Kubernetes, multi-tenancy, data lake — **solo al raggiungimento delle soglie quantitative** indicate in §13. Se le soglie non sono raggiunte, la v5.0 non si fa e si continua a migliorare la v4.x.

---

## 15. Product strategy

**Target:** team SOC piccoli (2-10 analisti) e MSP che non possono permettersi una piattaforma commerciale ma hanno bisogno di detection vera, non di una dashboard che mostra log.

**Problema risolto:** Aegis copre EDR + SIEM + SOAR in un singolo stack installabile. La maggior parte dei progetti open source copre un pezzo e richiede tre integrazioni per funzionare.

**Differenziatore reale:** l'hardening dei default. Secret obbligatori, fail-closed sulla revoca, immagini pinnate, CSP. È raro e verificabile — chi valuta un prodotto di sicurezza guarda esattamente questo.

**Il differenziatore che manca:** la deception. Oggi Aegis è "un altro EDR+SIEM". Con Kraken integrato diventa "rilevi l'attacco in corso e vedi cosa sta facendo l'attaccante in una sandbox". Questo è un messaggio di vendita diverso.

**Cosa aumenta davvero l'adozione:**
1. **Licenza.** Senza, zero adozione aziendale. È il primo lavoro.
2. **`docker compose up` che funziona.** Il README promette "one command". Va verificato su una macchina pulita, non su una macchina di sviluppo.
3. **Demo riproducibile.** `docs/DEMO.md` esiste — va verificato che funzioni da zero.
4. **Regole Sigma utili.** 14 regole non bastano per un SIEM. Servono 50+ con casi di test.
5. **Report leggibili.** Un PDF che un manager capisce vale più di dieci dashboard.

**Cosa NON fare:** non aggiungere feature prima di aver chiuso i finding bloccanti. Non dichiarare "production-ready" finché la suite non è verde al 100% in CI con i service container.

---

## 16. Quick wins — 7 giorni

1. **LICENSE** (Apache-2.0). Un'ora di lavoro, sblocca tutta l'adozione.
2. **Kraken: validatore secret** con marker `changeme`. Copiare `config.py:218-222` di Aegis. Due ore.
3. **Kraken: `${VAR:?}`** nel compose al posto dei fallback. Un'ora.
4. **Kraken: PyJWT** al posto di python-jose. Mezza giornata, la suite torna a collezionarsi.
5. **Aegis: fail-closed** su `RevokedCert`. Un'ora.
6. **Cancellare `aegis-brain/app;C`** e `nyx.db`/`main.js` da Kraken.
7. **Documentare** che le porte sensori Kraken sono su `0.0.0.0` per design.

## 17. Piano — 30 giorni

1. Contratto eventi v1 con schema versionato e test di compatibilità.
2. Kraken nel monorepo come `kraken/`, job CI separati.
3. Rimozione Docker socket: socket proxy con allowlist di operazioni.
4. Ingestione Kraken → Brain end-to-end con test.
5. Audit log unificato.
6. Suite Aegis verde al 100% in CI con service container Postgres/Redis.
7. 5 nuove regole Sigma con casi positivi e negativi.
8. `docker compose up` verificato su macchina pulita.

## 18. Piano — 90 giorni

1. Sandbox Kraken come job asincrono per file/ZIP in Aegis Total.
2. Object storage per campioni con retention.
3. DNS/firewall policy engine con TTL, dry-run, approvazione, rollback.
4. Rimozione azione `script` dai playbook.
5. Dashboard deception integrata.
6. Threat model aggiornato che includa Kraken.
7. Runbook operativo e piano di disaster recovery testato.

---

## 19. Rischi residui

| Rischio | Probabilità | Impatto | Mitigazione |
|---|---|---|---|
| Fuga dalla sandbox honeypot | Bassa | Alto | cap_drop ALL, network none, no socket condiviso |
| Compromissione via Docker socket | Media (oggi) | Critico | Rimozione in v4.1.0 |
| JWT forgiato con chiave `changeme` | Alta se non corretto | Critico | KRAKEN-SEC-001 |
| Test rotti nascosti da skip | Media | Medio | CI con service container |
| Divergenza Aegis/Kraken | Alta | Medio | Monorepo |
| Assenza licenza | Certa | Alto (prodotto) | AEGIS-SEC-004 |

**Decisioni che richiedono approvazione umana:**
1. Scelta della licenza (Apache-2.0 vs AGPL-3.0) — decisione commerciale, non tecnica.
2. Se abilitare `PLAYBOOK_SCRIPT_ENABLED` in qualche deployment.
3. Se le porte honeypot devono essere esposte a Internet o solo a una rete di deception dedicata.
4. Se la v5.0 (Kafka/K8s) va finanziata o rinviata a requisiti misurati.

---

## 20. Appendice — comandi, test e file realmente analizzati

### Comandi eseguiti

| Comando | Esito |
|---|---|
| `git rev-parse --abbrev-ref HEAD` | `dev` (Aegis), `main` (Kraken) |
| `git log -1` | `c9831c5` / `7fd50a9` |
| `git status --porcelain` | Aegis: solo `.perch/`; Kraken: `main.js`, `nyx.db` |
| `git ls-files` | 489 file tracciati (Aegis) |
| `git ls-files --error-unmatch .env` | non tracciato (corretto) |
| `python -m pytest tests --collect-only -q` | 787 test collezionati |
| `python -m pytest tests -q --timeout=120` | **5 failed, 572 passed, 210 skipped** (198,82s) |
| `python -m pytest tests -q` (Kraken) | **ImportError** — non collezionabile |
| `Get-ChildItem` ricorsivi, `Select-String` su pattern di sicurezza | vedi file sotto |

### Test realmente passati / falliti

| Suite | Passed | Failed | Skipped | Note |
|---|---|---|---|---|
| Aegis Brain (pytest) | 572 | 5 | 210 | fallimenti = `ConnectionRefusedError` (no PG/Redis locale) |
| Kraken (pytest) | — | — | — | non eseguibile (ImportError su `jose`) |
| Aegis Guard (JUnit) | — | — | — | **non eseguito** |
| NodeTrace | — | — | — | **non eseguito** |
| Frontend e2e (Playwright) | — | — | — | **non eseguito** |
| CI pipeline | — | — | — | **non eseguita** |

### Copertura dell'analisi

| Area | Copertura | Note |
|---|---|---|
| `aegis-brain/app/core/` | Alta | config, security, deps, agent_deps letti integralmente |
| `aegis-brain/app/api/v1/` | Media | auth.py integrale; deploy.py, total.py, playbooks.py, ingest.py, ws.py per pattern |
| `aegis-brain/app/rules/` | Media | engine.py integrale; rule_definitions.py per struttura; 14 Sigma + 5 correlazione elencate |
| `aegis-brain/app/services/` | Media | playbook_engine.py integrale; altri per pattern |
| `aegis-brain/tests/` | Media | 57 file elencati, eseguiti; conftest letto |
| `aegis-brain/alembic/` | Bassa | 19 migrazioni contate, **non lette una per una** |
| `aegis-guard/` | **Bassa** | struttura e pom.xml visti; **68 file Java non letti** |
| `aegis-link/` | Media | struttura completa, 16 file; contenuto per pattern |
| `NodeTrace/` | **Bassa** | solo struttura |
| `aegis-ebpf/` | **Non analizzata** | 16 file, non ispezionati |
| `frontend/` | **Bassa** | package.json e struttura; **23 .tsx non letti** |
| `kraken/app/` | Alta | config, security, docker_manager, containers.py integrali |
| `kraken/honeypot/` | Media | ssh_sensor per pattern; http/ftp/telnet **non letti** |
| `kraken/docker-compose.yml` | Alta | letto per intero |
| `kraken/nginx/` | Alta | nginx.conf integrale |
| `kraken/tests/` | **Nulla** | non eseguibili |
| `kraken/app/services/report_pro.py` | **Non analizzato** | 33 KB, non letto |

### File analizzati in dettaglio

**Aegis:** `app/core/config.py` (234 righe, integrale) · `app/core/security.py` (196, integrale) · `app/api/v1/auth.py` (356, integrale) · `app/rules/sigma/engine.py` (222, integrale) · `app/services/playbook_engine.py:200-339` · `docker-compose.yml` (222, integrale) · `Caddyfile` (integrale) · `.github/workflows/ci.yml` (per struttura) · `app/api/v1/deploy.py` (per pattern + righe 44-60) · `app/api/v1/total.py` (per pattern) · `app/core/deps.py`, `agent_deps.py`, `ws.py` (per pattern) · `pytest.ini`, `requirements.txt`, `.gitignore`, `conftest.py` (per pattern).

**Kraken:** `app/core/config.py` (104, integrale) · `app/core/security.py` (103, integrale) · `app/services/docker_manager.py` (223, integrale) · `app/api/v1/endpoints/containers.py` (96, integrale) · `docker-compose.yml` (250, integrale) · `nginx/nginx.conf` (integrale) · `.env.example` (integrale) · `Dockerfile.sandbox`, `sandbox-init.sh` (integrali) · `honeypot/runner.py` (integrale) · `honeypot/sensors/ssh_sensor.py` (per pattern) · `requirements.txt` (integrale).

### Dichiarazioni esplicite di non verifica

- **Non ho eseguito la CI** di nessuno dei due progetti.
- **Non ho eseguito i test Java** di aegis-guard (134 JUnit dichiarati nel README).
- **Non ho eseguito** i test NodeTrace né gli e2e Playwright.
- **Non ho avviato container** né eseguito migrazioni.
- **Non ho letto** i 68 file Java di aegis-guard, i 23 componenti `.tsx` del frontend, i 16 file eBPF, `report_pro.py` di Kraken.
- **Non ho verificato** se la CI di Aegis esegua i 210 test skippati con service container.
- **Non ho verificato** il contenuto di `docs-private/` (9 file) né di `docs/` (13 file) oltre ai nomi.
- Nessuna vulnerabilità è stata dichiarata sulla base di un LLM: ogni finding deriva da codice letto o comando eseguito.

