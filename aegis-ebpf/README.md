# Aegis kernel sensors — event-driven telemetry

This directory contains the event-driven kernel sensors. The unified Go agent is
the primary consumer in 4.3. The legacy Guard (Java) and NodeTrace (Python)
consumers remain in the source tree for 4.2.1 compatibility; they are **not**
shipped in the 4.3 bundle and are not offered by the 4.3 deployment UI.

| Sensor | Source | State |
|---|---|---|
| `aegis_exec.bpf.c` + `aegis_collector.c` (Linux) | `sched_process_exec` tracepoint + `do_exit` kprobe + `sock/inet_sock_set_state` tracepoint (ESTABLISHED only), ring buffer | **Verified**: `EBPF_TEST_PASS` + 100/100 benchmark without loss; TCP `127.0.0.1:18923` connections captured |
| `aegis_etw.c` (Windows) | `Kernel-Process` ID 1/2 + `Kernel-Network` TcpIp Connect via TDH | Builds cleanly (MinGW); runtime requires an admin trace session — lab validation |
| macOS | EndpointSecurity (System Extension + Apple entitlement) | **Not implemented here**: requires the `com.apple.developer.endpoint-security.client` entitlement, provisioning and a macOS lab — the `MacOSProcessMonitor` polling fallback (Tier 3) remains |
| Unified Go agent | `aegis-agent/internal/kernel` + `internal/guard/etw` | Starts `aegis-collector` when eBPF is configured; consumes `aegis-etw.exe` on Windows; falls back to auditd/polling and declares `quality=degraded:...` when a helper is missing |
| Legacy Guard | `ExternalEventIngester` pipe/file JSON | 4.2.1 source compatibility only; not in the 4.3 bundle |
| Legacy NodeTrace | `services/ebpf.py` subprocess collector → `POST /telemetry/report[/batch]` | 4.2.1 source compatibility only; not in the 4.3 bundle |

## Why no JNI for ETW (documented decision)

The original plan called for a JNI wrapper (`aegis_etw.dll` called from Java).
We chose pipe/stdout + `ExternalEventIngester` instead: the same JSON and the
same pipeline without the risk of a JVM crash from native code, no JNI toolchain
in the build, and the real constraint (a kernel trace session requires admin)
is identical either way. JNI adds no detection; it only adds a failure surface.
The Go agent keeps the same design: it spawns the helper and reads its stdout.

## Per-OS matrix (consistency)

| OS | Tier 1 kernel events | Tier 2 | Tier 3 fallback | Remediation |
|---|---|---|---|---|
| Linux | Verified eBPF → unified Go consumer | — | JNA/proc polling | Unified agent (user-mode) |
| Windows | ETW Kernel-Process (code ready, admin lab to validate) | Security log 4688 (requires audit policy) | Toolhelp32 polling | Unified agent (user-mode) |
| macOS | EndpointSecurity (Apple entitlement + MDM required) | — | `MacOSProcessMonitor` polling | Unified agent (user-mode) |

All Tier 1 sources speak the **single contract** below: same fields, same
`event_type`, same MITRE/SOAR rules on the Brain. Only the kernel source changes.

## Event contract (toward the Brain)

One JSON line per event, with the same fields as `EventSchema`:

```json
{"ts_ns":170527184458021,"pid":266393,"ppid":266389,"uid":0,"comm":"echo","filename":"/bin/echo","event_type":"PROCESS_CREATED"}
{"ts_ns":169800307442423,"pid":251040,"ppid":0,"uid":0,"comm":"sleep","filename":"","event_type":"PROCESS_EXITED","exit_code":0}
```

Per-OS field mapping (`event.schema.json` is authoritative; `check-contract.py`
validates it):

| Field | eBPF Linux | ETW Windows |
|---|---|---|
| `ts_ns` | `bpf_ktime_get_ns` (monotonic) | FileTime → Unix ns (wall-clock) |
| `pid`/`ppid` | tracepoint / `real_parent->tgid` | `ProcessID` / `ParentProcessID` via TDH |
| `uid` | `bpf_get_current_uid_gid` | always `0` (SIDs are not mapped in the MVP) |
| `comm` | `bpf_get_current_comm` | basename of `ImageName` |
| `filename` | `__data_loc` tracepoint | full `ImageName` |
| `exit_code` | `do_exit` argument | `ExitStatus` (TDH read, best-effort) |

The Go agent converts them into `EventSchema` reports and sends them to the
Brain as `PROCESS_CREATED`/`PROCESS_EXITED`/`CONNECTION_ESTABLISHED` — the same
MITRE/SOAR rules, no server change.

## Packaging and runtime integration (4.3)

The unified release archives carry the helpers with the agent:

- **Windows** `unified-latest.zip`: `aegis-agent.exe`, `aegis-etw.exe`. The
  one-liner sets `AEGIS_ETW_ENABLED=true`, an absolute `AEGIS_ETW_PATH` and
  `AEGIS_ETW_ALLOW_UNSIGNED=true` because the locally built helper has no
  Authenticode signature.
- **Linux** `unified-latest.tar.gz`: `aegis-agent`, `aegis-collector`,
  `aegis_exec.bpf.o`. When both helpers are present, the one-liner writes
  `NODETRACE_EBPF=1`, `NODETRACE_EBPF_COLLECTOR` and `NODETRACE_EBPF_OBJ` into
  `aegis.env`.

The Go agent only activates eBPF when the collector path is configured and the
kernel probe is not `absent`; it only activates ETW when the helper exists and
the opt-in is set. If either is missing, it keeps polling/auditd and reports the
degradation instead of claiming a kernel stream. The eBPF object is built with
CO-RE (`bpf_core_read`), so an object built against one BTF-enabled kernel can
run on another kernel that exposes the same tracepoints/kprobe. The Linux target
needs `libbpf1` and `CAP_BPF` + `CAP_PERFMON` (or root).

## Build and test (Linux)

```bash
# vmlinux.h is generated from the target kernel BTF (never committed).
docker run --rm --privileged -v $PWD:/src debian:bookworm-slim bash /src/build-in-docker.sh
docker run --rm --privileged -v $PWD:/src debian:bookworm-slim \
  bash -c 'apt-get update -qq; apt-get install -y -qq libbpf1; bash /src/test-ebpf.sh'
```

Runtime requirements: kernel >= 5.8, `/sys/kernel/btf/vmlinux`, `CAP_BPF` +
`CAP_PERFMON` (or `--privileged`). Note: `sched_process_exit` no longer exists
on recent kernels, so exit events use `kprobe/do_exit`.

## Measured performance (`bench.sh`, 300 executions of `/bin/true`, kernel 6.6)

| Metric | Value |
|---|---|
| Baseline without the sensor | 214 ms / 300 exec |
| With the sensor active | 246 ms / 300 exec (+15% wall-clock, ~0.1 ms per exec) |
| Lost events | **0** (created 300/300, exited 300/300) |
| Total collector CPU | 3 ticks (~30 ms for the whole run) |

This is a worst-case micro-benchmark (`true` does nothing but start and exit, so
the tracepoint cost dominates); on real workloads it is negligible. The Guard
user-mode path was also made lighter: a light scan every second (no hashes/paths
for every process), exe+SHA only for **new** processes, `ss`/`netstat` at most
every 5 s (`AEGIS_NETSTAT_INTERVAL_MS`), and UID caching (no `/etc/passwd` scan
per process).

## Windows (admin lab)

```cmd
gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh -lws2_32
aegis-etw.exe > events.jsonl
```

The release CI cross-compiles the same source with
`x86_64-w64-mingw32-gcc`.

## Honest limits (this is not a driver yet)

* User-mode remains for remediation/heartbeat/config; the kernel only provides
  event-driven telemetry. Real tamper protection requires a signed driver
  (WHQL) or a System Extension — out of scope for this phase.
* Isolation is via the OS firewall, not WFP callouts/eBPF TC.
* OTA signing is Ed25519; the old symmetric HMAC path is not reintroduced.
