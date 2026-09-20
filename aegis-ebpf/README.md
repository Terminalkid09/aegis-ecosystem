# Aegis kernel sensors — fuori dal user-mode polling

Questa cartella contiene i sensori event-driven. Il Guard Java resta come
fallback/transport, ma la telemetria primaria su Linux e Windows viene dal
kernel: niente snapshot, niente processi persi tra due poll.

| Sensore | Sorgente | Stato |
|---|---|---|
| `aegis_exec.bpf.c` + `aegis_collector.c` (Linux) | tracepoint `sched_process_exec` + kprobe `do_exit` + tracepoint `sock/inet_sock_set_state` (solo ESTABLISHED), ringbuf | **Verificato**: `EBPF_TEST_PASS` + bench 100/100 senza loss, connessioni 127.0.0.1:18923 catturate |
| `aegis_etw.c` (Windows) | `Kernel-Process` ID 1/2 + `Kernel-Network` TcpIp Connect via TDH | Compila pulito (mingw), runtime richiede admin — validazione in lab |
| macOS | EndpointSecurity (System Extension + entitlement Apple) | **Non implementato qui**: richiede entitlement `com.apple.developer.endpoint-security.client`, provisioning e lab macOS — resta il polling `MacOSProcessMonitor` (Tier 3) |
| Guard `ExternalEventIngester` | pipe/file JSON dei collector | test Java, include righe reali del collector |
| NodeTrace `services/ebpf.py` | sottoprocesso collector → `POST /telemetry/report[/batch]` | test Python + golden kernel; opt-in `ebpf_enabled` |

## Perché niente JNI per ETW (decisione documentata)

Il piano originale chiedeva un wrapper JNI (`aegis_etw.dll` chiamato da Java).
Scelto il pipe/stdout + `ExternalEventIngester` perché: stesso JSON e stessa
pipeline senza rischio crash JVM da codice nativo, niente toolchain JNI nel
build, e il blocco reale (sessione kernel = admin) resta identico in entrambi
i casi. JNI non aggiunge detection, aggiunge solo superficie di rottura.

## Matrice per-OS (coerenza)

| OS | Tier 1 kernel events | Tier 2 | Tier 3 fallback | Remediation |
|---|---|---|---|---|
| Linux | eBPF verificato → Guard ingester + NodeTrace forward | — | polling JNA/proc | Guard (user-mode) |
| Windows | ETW Kernel-Process (codice pronto, lab admin da validare) | Security log 4688 (richiede audit policy) | polling Toolhelp32 | Guard (user-mode) |
| macOS | EndpointSecurity (serve entitlement Apple + MDM) | — | polling `MacOSProcessMonitor` | Guard (user-mode) |

Tutti i Tier 1 parlano il **contratto unico** sotto: stessi campi, stessi
`event_type`, stesse regole MITRE/SOAR sul brain. Ciò che cambia è solo la
sorgente kernel.

## Contratto eventi (verso il brain)

Una riga JSON per evento, stessi campi di `EventSchema`:

```json
{"ts_ns":170527184458021,"pid":266393,"ppid":266389,"uid":0,"comm":"echo","filename":"/bin/echo","event_type":"PROCESS_CREATED"}
{"ts_ns":169800307442423,"pid":251040,"ppid":0,"uid":0,"comm":"sleep","filename":"","event_type":"PROCESS_EXITED","exit_code":0}
```

Mappatura campi per-OS (`event.schema.json` fa fede, `check-contract.py` valida):

| Campo | eBPF Linux | ETW Windows |
|---|---|---|
| `ts_ns` | `bpf_ktime_get_ns` (monotonic) | FileTime → unix ns (wall-clock) |
| `pid`/`ppid` | tracepoint / `real_parent->tgid` | `ProcessID` / `ParentProcessID` via TDH |
| `uid` | `bpf_get_current_uid_gid` | sempre `0` (SID non mappati in MVP) |
| `comm` | `bpf_get_current_comm` | basename di `ImageName` |
| `filename` | `__data_loc` tracepoint | `ImageName` completo |
| `exit_code` | arg `do_exit` | `ExitStatus` (lettura TDH, best-effort) |

Il Guard li converte in `SystemEvent` (`ExternalEventIngester`) e li invia al
brain come `PROCESS_CREATED` — stesse regole MITRE/SOAR, zero cambi server.

## Build e test (Linux)

```bash
# vmlinux.h è generato dal BTF del kernel target (mai committato)
docker run --rm --privileged -v $PWD:/src debian:bookworm-slim bash /src/build-in-docker.sh
docker run --rm --privileged -v $PWD:/src debian:bookworm-slim \
  bash -c 'apt-get update -qq; apt-get install -y -qq libbpf1; bash /src/test-ebpf.sh'
```

Requisiti runtime: kernel >= 5.8, `/sys/kernel/btf/vmlinux`, `CAP_BPF` +
`CAP_PERFMON` (o `--privileged`). Nota: il tracepoint `sched_process_exit`
non esiste più sui kernel recenti — per l'exit usiamo `kprobe/do_exit`.

## Performance misurate (`bench.sh`, 300 exec di /bin/true, kernel 6.6)

| Metrica | Valore |
|---|---|
| Baseline senza sensore | 214 ms / 300 exec |
| Con sensore attivo | 246 ms / 300 exec (+15% wall-clock, ~0.1 ms per exec) |
| Eventi persi | **0** (created 300/300, exited 300/300) |
| CPU collector totale | 3 ticks (~30 ms per l'intero run) |

È un micro-benchmark worst-case (`true` non fa altro che nascere e morire,
quindi il costo del tracepoint domina); su carichi reali è trascurabile.
Il Guard user-mode invece è stato alleggerito così: scan leggero ogni
secondo (niente più hash/path per tutti i processi), exe+SHA solo sui
processi NUOVI, `ss`/`netstat` al massimo ogni 5 s (`AEGIS_NETSTAT_INTERVAL_MS`),
UID in cache (niente più scansioni `/etc/passwd` per processo).

## Windows (lab admin)

```cmd
gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh
aegis-etw.exe > events.jsonl
```

## Limiti onesti (non è ancora un driver)

* User-mode resta per remediation/heartbeat/config; il kernel dà solo
  telemetria event-driven. Tamper protection vera richiede driver firmato
  (WHQL) / System Extension — fuori scope di questa fase.
* Isolamento via firewall OS, non WFP callout/eBPF TC.
* Firma OTA simmetrica (HMAC), non PKI.
