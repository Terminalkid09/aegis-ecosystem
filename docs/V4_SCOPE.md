# Aegis v4.0.0 — Scope e definizione di "fatto"

Documento di contratto. **La lista qui sotto è chiusa**: le idee nuove vanno in
"v4.1+", non dentro la release. Questo documento esiste perché uno scope aperto
con una visione grande è il modo più affidabile di non rilasciare mai.

Data freeze scope: 2026-09-15. Data release obiettivo: 2026-09-22.

## 0. Posizionamento (onesto)

Aegis v4.0.0 è un **lightweight SIEM con SOAR**, non un EDR e non un SIEM
enterprise. Raccoglie log da sorgenti eterogenee, li normalizza su uno schema
unico (OCSF-aligned), ci esegue regole **Sigma** e regole di **correlazione
multi-evento**, li rende **cercabili**, e dalle detection fa partire alert e
playbook esistenti.

Perché non "EDR": la prevenzione inline richiede driver firmati (EV cert,
attestazione Microsoft, entitlement Apple). Il progetto **non** lo fa e lo
dichiara. La telemetria profonda dell'host è comunque ottenuta **senza
driver** (ETW + AMSI su Windows, eBPF su Linux).

Perché non "SIEM enterprise": lo storage è PostgreSQL, non un motore di
ricerca distribuito. Il limite di scala è misurato e documentato
(`docs/ARCH_REVIEW.md`), con la via di migrazione indicata.

## 1. Definizione di "fatto" (must-have)

| # | Modulo | Criterio di accettazione |
|---|---|---|
| 1 | **Parser registry + normalizzazione** | ≥8 parser (`syslog`, `json`, `windows_event`, `zeek`, `suricata`, `squid`, `nginx`, `pfsense`) dietro un registry; ogni parser ha test con log reali di esempio; l'output è un evento unificato OCSF-aligned |
| 2 | **Ingestion** | `POST /api/v1/ingest/{source}` (auto-detect o parser esplicito) + listener **syslog UDP/TCP** configurabile; ogni sorgente ha stato, contatori e last-seen esposti |
| 3 | **Motore Sigma** | Carica regole Sigma YAML, mappa i campi Sigma→Aegis, supporta modificatori (`contains/startswith/endswith/re/gt/lt`) e condizioni (`and/or/not`, `1 of them`, `all of them`); bundle di regole Windows reali incluse; test per ogni regola inclusa |
| 4 | **Correlazione multi-evento** | Regole `threshold` (N eventi in T su un gruppo) e `sequence` (A poi B in T) su stato Redis; ≥3 regole demo (brute force, service creation post-logon, port sweep) con test |
| 5 | **Store + ricerca** | Tabella eventi con indice su `(timestamp, source)`; `POST /api/v1/search/events` con filtro tempo/sorgente/severità/campo/testo + paginazione; `GET /api/v1/search/stats` (EPS, top sources, top field) |
| 6 | **Pipeline detection → SOAR** | Una detection Sigma/correlazione crea un alert che entra nella pipeline esistente (dedup, suppression, playbook, UI) senza modifiche ai consumer |
| 7 | **Dato reale dal lab** | Collector **Windows Event Log** funzionante sul PC di sviluppo che invia eventi reali (4624/4625/7045…) all'endpoint di ingest — **ESEGUITO**: canale `System`, 10 eventi `7045` reali → `stored=10` in `siem_events` (2026-09-16). Sul canale `Security` serve una shell elevata |
| 8 | **Demo riproducibile** | `scripts/siem_demo.py` invia sample **nei formati reali** (Zeek, Suricata, syslog RFC5424, Windows Event JSON) marcati come sintetici in docs; `--dry-run` per ispezionare i payload |
| 9 | **UI** | Pagina *Log Sources* (sorgenti, EPS, health, istruzioni di invio) + pagina *Search* (query, filtri, risultati, dettaglio) |
| 10 | **Validazione** | Tutte le suite verdi; `docs/VALIDATION.md` aggiornato con i numeri del SIEM; test per parser, Sigma, correlazione, search |

## 2. Sorgenti realmente disponibili in questo lab

Vincolo dichiarato: nessuna infrastruttura esterna (niente firewall
enterprise, niente Zeek/Suricata installati). Quindi:

| Sorgente | Tipo | Come |
|---|---|---|
| Windows Event Log (Security/System/Application) | **REALE** | `scripts/winevent-collector.ps1` sul PC di sviluppo (`wevtutil`/PowerShell) → POST `/ingest/windows_event` |
| Windows Firewall log (`pfirewall.log`) | **REALE** (se il log è abilitato) | Stesso collector, `-FirewallLogPath`, → POST `/ingest/windows_firewall` |
| Eventi degli agenti (NodeTrace/Guard) | **REALE** | Pipeline esistente |
| Netflow/processi agenti | **REALE** | NodeTrace `network_flows` / processi |
| Zeek `conn/dns/http/ssl` | **SINTETICO** | `scripts/siem_demo.py` (sample di formato reale) |
| Suricata `eve.json` | **SINTETICO** | `scripts/siem_demo.py` |
| Syslog RFC3164/5424 | **MISTO** | Listener reale; sample di formato reale per il volume |
| Squid/nginx access log | **SINTETICO** | `scripts/siem_demo.py` |
| pfSense `filterlog` / iptables | **SINTETICO** | `scripts/siem_demo.py` |

I sample sintetici sono dichiarati tali in `docs/VALIDATION.md`: servono a
dimostrare i parser e la pipeline, **non** a produrre metriche di detection su
traffico reale.

## 3. Fuori scope (→ v4.1+)

Elencati perché *non* vanno aggiunti a metà lavoro:

- ClickHouse / Elasticsearch / motore di ricerca distribuito
- Linguaggio di query completo stile KQL/SPL (in v4.0 c'è un filtro strutturato)
- Multi-tenancy e SSO/SAML
- Telemetria ETW-TI / driver kernel / prevenzione inline / firma EV
- Connettori cloud (CloudTrail, Entra ID, O365)
- Threat-intel feed commerciali
- Dashboards SOC grafiche avanzate
- macOS (richiede entitlement Apple)

## 4. Come sapremo che è pronto

```bash
# Demo end-to-end sui sample (dichiara i sample come sintetici)
python scripts/siem_demo.py --scenario all --api-key "$AEGIS_API_KEY"
python scripts/siem_demo.py --scenario bruteforce --dry-run   # ispeziona i payload

# Log reali dal PC di sviluppo (Windows Event Log + firewall)
pwsh -File scripts/winevent-collector.ps1 -BaseUrl http://127.0.0.1:8000 -ApiKey $env:AEGIS_API_KEY

# Un evento reale può anche entrare a mano, per provare un parser nuovo
curl -X POST http://127.0.0.1:8000/api/v1/ingest/auto \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"EventID":4625,"TargetUserName":"administrator"}'

# Tutte le suite
pytest aegis-brain/tests/ -q
cd frontend && npm run build && npm run lint
```

Il criterio finale non è "quante feature ci sono" ma: **un evento reale del
mio PC entra, viene normalizzato, genera una detection Sigma, e la vedo in
dashboard con il contesto correlato.**
