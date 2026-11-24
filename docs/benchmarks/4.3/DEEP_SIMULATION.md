# Deep simulation — Aegis/Kraken 4.3

Executed: `2026-11-23T17:36:24.297737+00:00` → `2026-11-23T17:48:41.780671+00:00`  
Stack: `http://127.0.0.1:8000` (Windows, MSI packages 4.3.0, self-signed)  
Total duration: **738s**

> Behaviour simulation, not malware execution. Every case is sent to the Brain
> as a real event through an agent enrollment flow. A dedicated agent per case
> prevents alert suppression (per agent/rule/process) from skewing the count.

## Detection

| Metric | Value |
|---|---:|
| Malicious cases | 39 |
| Benign cases | 46 |
| True positive | 38 |
| False negative | 1 |
| False positive | 0 |
| True negative | 46 |
| Precision | 1.000 |
| Recall | 0.974 |
| F1 | 0.987 |
| False positive rate | 0.000 |
| Correct severity | 23/28 |

### False negatives (behaviour not detected)

| Case | Technique | Note |
|---|---|---|
| `mal-linux-shadow` — shadow read | T1003.008 | T1003.008 has no static rule: expected FN |

### Severity differing from expected

| Case | Expected | Obtained |
|---|---|---|
| `mal-psh-encoded` | HIGH | CRITICAL |
| `mal-rundll32-js` | HIGH | LOW |
| `mal-threads` | MEDIUM | LOW |
| `mal-double-ext` | HIGH | CRITICAL |
| `mal-lolbin-temp` | HIGH | CRITICAL |

## Rules that raised alerts

| Rule | Alerts |
|---|---:|
| AEGIS-S012 | 12 |
| AEGIS-S004 | 11 |
| AEGIS-S009 | 11 |
| AEGIS-S001 | 8 |
| AEGIS-S021 | 3 |
| AEGIS-S015 | 2 |
| AEGIS-S007 | 2 |
| AEGIS-S002 | 2 |
| AEGIS-S016 | 2 |
| AEGIS-S017 | 2 |
| AEGIS-S019 | 2 |
| AEGIS-S018 | 2 |
| AEGIS-S013 | 1 |
| AEGIS-S011 | 1 |
| AEGIS-S020 | 1 |
| AEGIS-S010 | 1 |
| AEGIS-S014 | 1 |
| AEGIS-S006 | 1 |

## Soak

| Metric | Value |
|---|---:|
| Agents | 10 |
| Duration | 120.1s |
| Requests | 15860 |
| Accepted | 15860 |
| Duplicates | 0 |
| Errors | 0 |
| Throughput | 132.07 rps |
| p50 / p95 / p99 | 74.1 / 98.0 / 178.5 ms |
| Lost events (server) | None |

## Functional checks

| Check | Result | Detail |
|---|---|---|
| all cases sent with 200 | PASS | examples=[] |
| heartbeat 200 | PASS | 200 |
| duplicate event_id recognised | PASS | 200 status=duplicate |
| payload without event_type rejected 422 | PASS | 422 |
| wrong agent secret rejected | PASS | 401 |
| command_line over the limit truncated, not 422 | PASS | 200 |
| 600 processes accepted (list truncated, not 422) | PASS | 200 |
| process list truncated to 500 in the DB | PASS | rows=500 |
| NUL in the command line does not break the write | PASS | 200 |
| unknown agent rejected | PASS | 401 |
| alert present among the unresolved | PASS |  |
| PATCH resolve 200 | PASS | {"id":645,"agent_id":"be6c6d1c-ed3e-4004-95d9-30efd0305f5e","agent_hostname":null,"timestamp":"2026-11-23T17:41:22.47323 |
| resolve reports active muting | PASS | triage_muted_seconds=604800 |
| resolve sets is_resolved | PASS | True |
| resolved alert no longer among unresolved | PASS |  |
| resolved alert present among resolved | PASS |  |
| detail consistent with the resolve | PASS |  |
| identical detection muted after resolve | PASS | 1->1 |
| alert reopen 200 | PASS | {"id":645,"agent_id":"be6c6d1c-ed3e-4004-95d9-30efd0305f5e","agent_hostname":null,"timestamp":"2026-11-23T17:41:22.47323 |
| after reopening, the detection is visible again | PASS | 1->2 |
| resolve-all 200 | PASS | {"resolved":59,"triage_muted":59,"detail":"Resolved 59 alerts; similar detections muted ~7d for triaged patterns"} |
| resolve-all idempotent (second call 0) | PASS | second=0 |
| viewer cannot run resolve-all (403) | PASS | 403 |
| viewer cannot delete alerts (403) | PASS | 403 |
| Kraken health 200 | PASS | 200 |
| Kraken ingest ssh 201 | PASS | 201 |
| Kraken ingest http 201 | PASS | 201 |
| Kraken ingest ftp 201 | PASS | 201 |
| Kraken ingest telnet 201 | PASS | 201 |
| Kraken ingest smb 201 | PASS | 201 |
| Kraken ingest rdp 201 | PASS | 201 |
| Kraken retry is idempotent: no second row | PASS | status=201 rows=315->315 |
| Kraken rejects a wrong internal key | PASS | 403 |
| Aegis sees the Kraken deception sessions | PASS | +6 |
| Aegis creates the Kraken incident | PASS | +6 |
| Kraken outbox delivered | PASS | pending=0 |
| Kraken alert resolvable from the Aegis dashboard | PASS | {"id":659,"agent_id":"02c99b74-b95e-4b2a-8ac2-b68180df0d16","agent_hostname":null,"timestamp":"2026-11-23T17:44:43.67710 |
| no plaintext password in Aegis incidents | PASS | rows=0 |
| soak without HTTP errors | PASS | errors=0 |
| soak without lost events | PASS | lost=None |

## Limitations

- Constructed events, not real traffic and no malware executed.
- The expected severity is the one defined by the 4.3 static-rule contract.
- The soak measures the HTTP+DB path on a single host; it is not a fleet
  capacity or a scalability proof.
- Kraken is exercised on the sensors→app→Aegis contract; it is not a honeypot
  exposure test on a real network.
- Persistence is not inferred from the delta of the `telemetry` table (a metrics
  table shared with other agents): it is verified through scenario snapshots and
  direct probes of the agent.
