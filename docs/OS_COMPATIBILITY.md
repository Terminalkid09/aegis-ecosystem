# Aegis — OS compatibility

Version 1.3 — 2026-11-20.

Decisions: Windows 11 and Server 2022/2025 are primary; Windows 10 is lab-only;
Ubuntu 22.04/24.04, Debian 12 and RHEL 9 use eBPF where available with an
explicit fallback; Android is excluded; macOS is **not supported for endpoint
telemetry** in 4.3 and is build/CI-only.

## 1. Supported matrix

| OS | Version | Tier 1 (kernel) | Tier 2 | Tier 3 fallback | Status |
|---|---|---|---|---|---|
| Windows 11 | 22H2+ | ETW Kernel-Process 1/2 + Kernel-Network TcpIp 12 (`aegis_etw.c`; MinGW 16.2, typed TDH/JSON) | Security log 4688 (audit policy required) | Toolhelp32 polling | **Primary; live elevated validation** (95 events); non-admin exit 2 |
| Windows Server 2022 / 2025 | — | Same as Windows 11 | Same as above | Polling | Primary; same code, live Server validation still required |
| Windows 10 | 22H2 | Same as above | Same as above | Polling | Compatibility/lab only |
| Ubuntu 22.04 / 24.04 | Kernel >= 5.8 + BTF | eBPF `sched_process_exec` + `do_exit` kprobe + `inet_sock_set_state` ESTABLISHED, ring buffer | — | JNA/proc polling | **WSL2 validated** (195 events, 300/300 benchmark, 0 lost); bare-metal validation pending |
| Debian 12 | Kernel >= 5.8 + BTF | Same as Ubuntu | — | Polling | Primary; bare-metal validation pending |
| RHEL 9 | Kernel >= 5.14 + BTF | Same as Ubuntu | — | Targeted auditd / polling | Primary; RHEL-family validation pending |
| Kali (WSL2) | Microsoft kernel | Same as Ubuntu | — | Polling | **Validated** (126 events); not a bare-metal test |
| macOS | — | Not supported (requires Apple EndpointSecurity entitlement) | — | Legacy Guard polling, not in the 4.3 bundle | **Build/CI-only; no endpoint telemetry**; no live hardware |
| Android | — | Not supported by decision | — | — | Excluded |

The reasons why eBPF/ETW are not universal and the cost of a driver are covered
in [KERNEL_AND_DRIVERS.md](KERNEL_AND_DRIVERS.md).

## 2. Verified runtime requirements

### Linux (eBPF)

* kernel >= 5.8, `/sys/kernel/btf/vmlinux` present, `CAP_BPF` +
  `CAP_PERFMON` (or `--privileged`);
* `vmlinux.h` generated from the target BTF and never committed;
* exit via `kprobe/do_exit` (the `sched_process_exit` tracepoint is absent on
  recent kernels);
* collector and eBPF object present in the bundle; without them the agent stays
  in polling/auditd mode and reports the degradation.

Validation on 2026-11-20: WSL2 Ubuntu and Kali, 195/126 events, TCP connections
and `REMOTE_OK`; Ubuntu benchmark 300/300 created and 300/300 exited, **0
lost**. WSL2 uses the Microsoft kernel, so this does not replace bare-metal
validation.

### Windows (ETW)

* build with `make aegis-etw.exe` or
  `gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh -lws2_32`;
* `-lws2_32` is required because `ntohl` comes from `winsock2.h`;
* the binary has a `requireAdministrator` manifest and a runtime check; without
  elevation it exits **2** and does not open the session;
* session `AegisKernelProcess`; an existing name fails with an actionable
  message instead of reusing an invalid handle (`--replace` is explicit);
* JSONL output to the Go agent consumer, without JNI.

Validation on 2026-11-20: **95 events** (45 created, 47 exited, 3 connections),
`remote=127.0.0.1:8000`, `exit_code=0`, `JSON_OK`. The ETW network event is a
connection attempt, not an established handshake. ETW is telemetry, not tamper
protection: a local administrator can stop the session or the service. The
hardening options and their limits are documented in
[KERNEL_AND_DRIVERS.md](KERNEL_AND_DRIVERS.md#hardening-that-does-not-require-a-driver).

### macOS

The unified Go agent has no macOS telemetry collector; `collector_other.go`
returns an explicit unsupported error. EndpointSecurity/System Extension is not
implemented, and there is no live Mac hardware. `GOOS=darwin` builds for amd64
and arm64 and the Darwin test compile/vet pass. The CI matrix includes
`macos-latest`; the hosted run is still required. The legacy Java
`MacOSProcessMonitor` is polling code and is **not in the 4.3 bundle**.

## 3. Sensor profiles

* **Profile A** — complete kernel source (BTF/eBPF or ETW available): event-driven,
  no snapshot.
* **Profile B** — partial kernel source (no BTF, ETW without admin): reduced
  sources, targeted polling, `auditd`/4688 only where configured.
* **Profile C** — user-mode polling only: explicitly degraded coverage.
* Rule: the active profile and missing sources must be visible in the dashboard
  (agent status + sensor health); degradation is never silent.

## 4. Install / upgrade / rollback

Windows (elevated PowerShell): `install.ps1` one-liner + enrollment token →
`C:\Aegis\aegis-agent.exe` with `aegis-etw.exe` → service; upgrade via signed
`UPDATE_AGENT` with staging. Linux (root): `install.sh` one-liner →
`/opt/aegis/aegis-agent` with collector and eBPF object →
`systemctl enable --now aegis-agent`; same OTA mechanism. Both use a short,
single-use token, persist no password, and do not compile on the target
(artifacts come from CI/`ARTIFACT_DIR`).

Agent rollback is outside 4.3.0; the supported rollback boundary is the server
plus a database restore.
