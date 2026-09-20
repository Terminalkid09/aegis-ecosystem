# Aegis — Event Schema v2 e pipeline affidabile (M1 Fase 2)

Versione: 1.0 — 2026-09-11.

## 1. Cosa cambia

Ogni evento ha identità (`event_id` UUID), versione (`schema_version`),
ancoraggio boot (`boot_id`) e sequenza (`seq` per coppia agent/boot),
doppio tempo (monotono `ts_ns` + wall-clock `ts_wall_ns`), start time
processo (`proc_start_ns`, risolve PID reuse con il solo pid), contesto
minimo (sessione, integrità), rete strutturata (proto/direzione) e
provenienza/qualità/sampling su Linux (container, cgroup, namespace).

## 2. Compatibilità backward/forward (verificata in CI)

| Chi | v1 (legacy) | v2 |
|---|---|---|
| `event.schema.json` | valido per sempre (solo `pid`+`event_type` obbligatori) | `schema_version=2` + campi opzionali tipati; `seq` richiede `boot_id` |
| `check-contract.py` | sample v1 dedicato, golden v1 intatte | sample v2 + 2 righe golden v2; `RESULT: ALL PASS` |
| Guard `ExternalEventIngester` | righe v1 mappate come prima (+`eventId` generato) | campi v2 mappati se presenti; `CONNECTION_ESTABLISHED` ora accettata |
| NodeTrace `ebpf.py` | invariato + `event_id` generato | pass-through tipato dei campi v2 |
| Brain `EventSchema` | invariato (tutti i v2 `Optional`) | alias camelCase, mai obbligatori |

Regola: producer v2 includono sempre `schema_version=2, event_id, agent_id,
boot_id, seq`; i consumer accettano righe senza (v1 implicita).

## 3. Pipeline locale e comportamento offline

* Batch 25 eventi / 500 ms (Guard) e 25 / 2 s (NodeTrace), fallback
  per-evento verso brain vecchi (`BatchUnsupportedException` su 404/405/501).
* Retry con jitter (Guard `AegisClient`: lineare + 0–250 ms, niente
  thundering herd dopo un outage).
* Buffer limitati: 2000 eventi in memoria (drop-oldest contato),
  spool cifrato 50 MB su disco (oltre: rifiuto contato).
* Server irraggiungibile: batch → spool AES-256-GCM (chiave derivata dal
  device secret, permessi 600 best-effort) → replay in ordine al ritorno.
  Reboot endpoint: lo spool sopravvive (test `roundTripSurvivesRestart`).
* Tamper: righe manomesse scartate e contate (GCM); chiave cambiata
  (re-enroll) → quarantena `spool.jsonl.bad-<ts>`, mai cancellazione.
* Server: dedup idempotente su `event_id` (finestra LRU 20000, limite onesto:
  reboot brain = finestra persa, solo doppio conteggio su retry a cavallo,
  mai perdita) + `SeqTracker` per gap/reset/late per (agent, boot).

## 4. Contatori (perdita misurata, mai invisibile)

* Agente: `EventOutbox.stats()` (`received/sent/buffered/droppedBufferFull/
  spooled/spoolReplayed/spoolCorrupt/sendFailed`), `KernelEventBatcher.stats()`.
* Server: `GET /telemetry/stats` → `events_duplicated, events_seq_gaps,
  events_seq_gap_events`; batch response con `duplicates`.
* Prossimo passo (Fase 8): health sensore e qualità dati in dashboard.

## 5. Overhead misurato (profili esistenti, `aegis-ebpf/README.md`)

eBPF: +15% wall-clock su micro-benchmark worst-case (300 exec `/bin/true`,
~0.1 ms/exec), 0 eventi persi, 30 ms CPU collector totali; su carichi reali
trascurabile. Guard user-mode alleggerito (scan 1 s, hash solo nuovi processi,
netstat ≤ ogni 5 s). Spool: AES-GCM ~µs/evento, force-to-disk solo su failure
path (non nel flusso caldo).

## 6. Residui onesti → fasi successive

Spool cifrato con chiave da device secret (rotazione = quarantena rileggibile
solo riottenendo il vecchio secret); dedup server in memoria (DB-backed in
valutazione Fase 6); visibilità contatori agent in dashboard (Fase 8).
