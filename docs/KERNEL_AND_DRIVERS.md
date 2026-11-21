# Aegis — Kernel sensors and driver feasibility

Version 1.1 — 2026-11-20.

This document defines:

1. what a "kernel sensor" means in Aegis;
2. why the same mechanism is not available on every machine;
3. the real cost of a kernel driver, in money and maintenance.

Summary: Aegis uses **eBPF on Linux** and **ETW on Windows**. It does not install
a kernel driver on either platform. macOS is **not supported for kernel or
endpoint telemetry** in the 4.3 unified agent; it is build/CI-only and has no
live hardware validation.

## 1. What a kernel sensor is

A kernel sensor receives events from the operating system when they happen,
instead of polling a process list. Aegis normalizes the events into one contract
(`PROCESS_CREATED`, `PROCESS_EXITED`, `CONNECTION_ESTABLISHED`) and sends them to
the Brain with the same schema.

| Platform | Source | How it is loaded | Required privilege |
|---|---|---|---|
| Linux | eBPF: `sched_process_exec` tracepoint, `do_exit` kprobe, `inet_sock_set_state` tracepoint | CO-RE eBPF object plus a user-mode collector | `CAP_BPF` + `CAP_PERFMON`, or root/`--privileged` |
| Windows | ETW: `Microsoft-Windows-Kernel-Process` 1/2, `Microsoft-Windows-Kernel-Network` TcpIp 12 | User-mode process that opens an ETW session | Administrator |
| macOS | No kernel source in the 4.3 bundle | No supported unified collector; legacy Guard polling is not part of the 4.3 bundle | — |

None of these rows is a driver. eBPF is bytecode verified by the kernel; ETW is
a tracing facility consumed from user mode. A driver is a different component
with a different lifecycle, signing process, stability risk and support cost.

## 2. Why Linux coverage is not universal

Verified runtime requirements:

- kernel **>= 5.8**;
- `/sys/kernel/btf/vmlinux` present (BTF);
- `CAP_BPF` and `CAP_PERFMON`, or root/`--privileged`;
- access to the tracepoints/kprobes used by the program;
- the collector and eBPF object present in the agent bundle.

The sensor does not start, or degrades explicitly, when:

- the kernel is older or has no BTF (some minimal images, appliances and custom
  kernels);
- a hardened kernel, grsecurity or an LSM policy denies loading;
- a container lacks the required capabilities;
- `sched_process_exit` is absent: Aegis already uses `kprobe/do_exit`;
- the host is WSL2: the kernel is Microsoft's kernel
  (`6.6.87.2-microsoft-standard-WSL2` in the test), not the distribution kernel.
  It works, but it is not equivalent to a bare-metal test.

Fallback is explicit: polling/auditd and `quality=degraded:...`; Aegis does not
pretend that a kernel stream is active when it is not.

### Coverage in practice

The mechanism covers the **majority of current LTS server fleets** when they run
a modern kernel with BTF: Ubuntu 22.04/24.04, Debian 12 and RHEL 9 are the
supported targets. It does **not** cover every Linux installation:

- Ubuntu 20.04 with the original 5.4 GA kernel, RHEL 8 (4.18) and Amazon Linux 2
  need a newer kernel/BTF or operate in degraded mode;
- minimal containers, appliances, embedded images and custom hardened kernels
  may not expose BTF or may block the probes;
- WSL2 is validated but is not a substitute for bare-metal validation.

This is a **medium** limitation for broad desktop/embedded coverage and a
**small** limitation for a modern server fleet. It is not a claim of 100%
coverage; the degraded state is visible and intentional.

### Evidence (WSL2, 2026-11-20)

| Distribution | Events | Process creations | Connections | Result |
|---|---:|---:|---:|---|
| Ubuntu (WSL2) | 195 | 36 | 16 | `EBPF_TEST_PASS`, `REMOTE_OK` |
| Kali (WSL2) | 126 | 26 | 15 | `EBPF_TEST_PASS`, `REMOTE_OK` |

Ubuntu benchmark: **300/300 exec created, 300/300 exited, 0 lost**,
`BENCH_PASS`. This is a WSL2 micro-measurement, not a bare-metal certification.

## 3. Why Windows ETW is not universal

ETW does not require a driver, but it requires **elevation**. The collector has a
`requireAdministrator` manifest and a runtime check; without administrator
rights it exits with code **2** without opening the session. A sensor that
starts but sees nothing would be worse than a clear error.

Other limits:

- an existing or policy-blocked ETW session can prevent startup;
- kernel providers may be absent or partially available;
- `Kernel-Network` event 12 is a **connection attempt**, not an established
  handshake; Aegis marks it `degraded:etw-connect-attempt`;
- ETW does not protect the agent process from being stopped; the agent's ETW
  supervisor restarts a helper whose stream ends, but this is availability
  hardening, not a tamper-proof boundary. Remediation remains user-mode;
- Windows Server and Windows 11 can have different providers and policies. The
  live test was performed on elevated Windows 11, not on Server.

### Security boundary: can malware disable ETW?

Yes. A local administrator can stop the trace session, stop the agent service or
kill the process. ETW is a telemetry source, **not a tamper-proof security
boundary**. A kernel-level or admin-level attacker can also disable auditing,
delete logs or replace binaries. Aegis 4.3 is a user-mode agent; it does not
claim to survive a fully privileged attacker.

This limitation is why production EDR products often add a signed kernel driver,
a protected process, a watchdog service and remote log forwarding. Those
controls raise the cost of tampering; they do not make an endpoint invulnerable.
For Aegis 4.3, the honest claim is: **detection and evidence, not guaranteed
survival against an administrator-level attacker**.

### Hardening that does not require a driver

Aegis 4.3 already raises the cost of silent tampering: the Windows installer
registers service recovery, the Linux unit uses `Restart=always`, the agent
reports `quality=degraded:...` when a source is missing, and telemetry is sent
to the Brain instead of being kept only on the endpoint. Additional controls can
be applied by the operator without writing a kernel driver:

- **Restrict local administrators.** WDAC/AppLocker allowlists, separate admin
  accounts, Credential Guard, LSA protection and Secure Boot reduce who can stop
  the service or replace the binary.
- **Forward security evidence off-host.** Windows Event Forwarding (WEC/WEF) for
  the Security log, or syslog/TLS to a remote collector, preserves evidence even
  if local logs are deleted. The Brain is already the remote destination for
  Aegis telemetry.
- **Watch the watcher.** Service recovery restarts a crashed agent; the Go
  agent now supervises the ETW helper and restarts it with bounded exponential
  backoff when the stream ends. The capability/sensor payload exposes
  `etw_watchdog`, `etw_restarts` and `etw_last_reason`, so a session loss is
  visible instead of silently falling back to polling. A local administrator
  can still stop the watchdog or the agent.
- **Keep the helper signed and least-privileged.** ETW runs elevated; the binary
  is checked with Authenticode unless explicitly allowed otherwise. OTA is
  Ed25519-signed.
- **Protect the process.** Windows Protected Process Light (PPL) and ELAM require
  Microsoft signing and a package outside 4.3; tamper-proof service protection
  or kernel network filtering requires a kernel driver.

These measures **raise cost and preserve evidence**; they do not make a
user-mode agent unkillable. If the acceptance criterion is "a local
administrator or kernel malware must not be able to disable telemetry", the
answer is a signed driver/protected service plus off-host collection, not a
configuration change. That is outside 4.3 and is recorded as a gap rather than
implied by the ETW label.

### Evidence (live ETW, 2026-11-20)

- **95 events** in `events.jsonl`;
- **45** `PROCESS_CREATED`;
- **47** `PROCESS_EXITED`;
- **3** connections with `remote=127.0.0.1:8000` and `exit_code=0`;
- `JSON_OK` on the contract;
- elevated execution with UAC;
- non-elevated execution: exit **2**, no session started.

## 4. macOS

Aegis does **not** implement EndpointSecurity on macOS:

- EndpointSecurity requires the
  `com.apple.developer.endpoint-security.client` entitlement, a System
  Extension, signing/notarization and Apple approval;
- no real Mac hardware is available for a live test;
- the unified Go agent has no macOS telemetry collector: `collector_other.go`
  returns an explicit "unsupported" error;
- the legacy Java `MacOSProcessMonitor` is polling code and is **not shipped in
  the 4.3 bundle**;
- `GOOS=darwin` builds (amd64 and arm64) and the Darwin test compile/vet pass.
  The CI matrix now includes `macos-latest`; the hosted run is still required.

macOS is therefore **build/CI-only** in 4.3. It is not a supported endpoint
telemetry platform, and the documentation does not present it as one.

## 5. Driver cost

"Zero cost" applies to eBPF and ETW: there is no licence to buy and no signature
required for the current path. It does not apply to a distributed driver.

| Platform | Monetary cost | Operational cost | Needed by Aegis? |
|---|---|---|---|
| Linux kernel module | No mandatory certificate; can be signed with a local key/MOK | Build per kernel, ABI maintenance, regression tests, Secure Boot conflicts | **No**: eBPF covers event-driven telemetry |
| Windows kernel driver (KMDF/WDM) | **EV code-signing certificate** (typically hundreds of USD/year), partner/Microsoft account, test lab | Kernel development, WHQL/attestation, BSOD support, compatibility with every Windows build | **No** for detection; only for tamper protection/WFP, outside 4.3 |
| macOS System Extension | Apple Developer Program (99 USD/year) plus an entitlement approved by Apple | Notarization, MDM, hardware and OS-version testing | **No** in this phase |

Prices are indicative and must be confirmed with the vendor. The point is not
the exact figure: a Windows driver is **not free**, and it adds a stability risk
and support obligation that ETW does not have.

## 6. Decision for 4.3

- **No driver** in the bundle.
- eBPF on Linux where the runtime requirements are present.
- ETW on Windows **only when elevated**.
- Polling/auditd as an explicit fallback.
- macOS build/CI-only; no endpoint telemetry claim.
- A Windows/macOS driver will be considered only for an explicit commercial
  requirement (tamper protection or kernel network filtering).

See also [OS compatibility](OS_COMPATIBILITY.md) and
[`aegis-ebpf/README.md`](../aegis-ebpf/README.md).
