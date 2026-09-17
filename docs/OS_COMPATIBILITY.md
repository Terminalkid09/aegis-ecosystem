# Aegis — OS Compatibility (M0)

Versione: 1.0 — 2026-09-11.
Decisioni: Windows 11 + Server 2022/2025 primari; Windows 10 solo lab;
Ubuntu 22.04/24.04, Debian 12, RHEL 9; eBPF completo dove possibile con fallback
esplicito; niente Android; niente macOS oltre il polling esistente.

## 1. Matrice supportata

| OS | Versione | Tier 1 (kernel) | Tier 2 | Tier 3 fallback | Stato |
|---|---|---|---|---|---|
| Windows 11 | 22H2+ | ETW Kernel-Process 1/2 + Kernel-Network TcpIp (`aegis_etw.c`: build verificata, runtime richiede admin) | Security log 4688 (richiede audit policy) | polling Toolhelp32 (`WindowsProcessMonitor`) | primario, validazione runtime lab in Fase 3 |
| Windows Server 2022 / 2025 | — | come Windows 11 | come sopra | polling | primario, Fase 3 |
| Windows 10 | 22H2 | come sopra | come sopra | polling | solo compatibilità/lab iniziale |
| Ubuntu 22.04 / 24.04 | kernel ≥5.8 + BTF | eBPF `sched_process_exec` + kprobe `do_exit` + `inet_sock_set_state` ESTABLISHED, ringbuf (verificato bench 300/300, 0 loss, kernel 6.6) | — | polling JNA/proc | primario, Fase 4 |
| Debian 12 | kernel ≥5.8 + BTF | come Ubuntu | — | polling | primario, Fase 4 |
| RHEL 9 | kernel ≥5.14 + BTF | come Ubuntu (test RHEL-family in Fase 4) | — | auditd mirato / polling | primario, Fase 4 |
| macOS | — | NON supportato (serve EndpointSecurity entitlement Apple) | — | `MacOSProcessMonitor` polling | lab only, fuori roadmap |
| Android | — | NON supportato per decisione | — | — | escluso |

## 2. Requisiti runtime verificati (`aegis-ebpf/README.md`, `build-in-docker.sh`)

* Linux: kernel ≥5.8, `/sys/kernel/btf/vmlinux` presente, `CAP_BPF` +
  `CAP_PERFMON` (o `--privileged`); `vmlinux.h` generato dal BTF target e mai
  committato (`.gitignore`); exit via `kprobe/do_exit` (il tracepoint
  `sched_process_exit` non esiste più sui kernel recenti).
* Windows: build `make aegis-etw.exe` oppure
  `gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh -lws2_32`.
  `-lws2_32` è obbligatorio: `ntohl` arriva da `winsock2.h`, senza la libreria il
  link fallisce con `undefined reference to __imp_ntohl`. Build verificata su
  MinGW-w64 15.2 (2026-09-16); l'**esecuzione** richiede una sessione admin
  (`StartTrace` restituisce 5 senza elevazione: il binario parte e fallisce in
  modo pulito, la sola parte mai eseguita è il consumo reale della trace);
  output `events.jsonl` → Guard
  `ExternalEventIngester` (niente JNI per decisione documentata: pipe/stdout,
  stesso JSON, niente crash JVM da nativo).
* NodeTrace forward eBPF: opt-in `ebpf_enabled`, sottoprocesso collector →
  `POST /telemetry/report[/batch]`; golden `tests/golden.jsonl` + `check-contract.py`.

## 3. Profili sensore (Fase 3/4, contratto)

* Profilo A — kernel completo (BTF/eBPF o ETW disponibili): event-driven, niente snapshot.
* Profilo B — kernel parziale (BTF assente, ETW senza admin): sorgenti ridotte, polling mirato, `auditd`/4688 solo dove configurato.
* Profilo C — solo polling user-mode: copertura dichiarata degradata.
* Regola: il profilo attivo e le sorgenti mancanti devono essere visibili in
  dashboard (stato agent + salute sensore, Fase 8); mai degrado silenzioso.

## 4. Installazione / upgrade / rollback per OS (verifica Fase 3/4)

Windows (admin PowerShell): one-liner `install.ps1` + enroll token →
`C:\Aegis\{Guard,NodeTrace}` → servizio; upgrade via `UPDATE_AGENT` firmato con
stage; rollback da artefatto precedente versionato. Linux (root): one-liner
`install.sh` → `/opt/aegis/*` → `systemctl enable --now aegis-agent`; stesso
meccanismo OTA. Entrambi: token breve monouso, niente password persistite,
nessuna compilazione sul target (artefatti da CI/`ARTIFACT_DIR`).
