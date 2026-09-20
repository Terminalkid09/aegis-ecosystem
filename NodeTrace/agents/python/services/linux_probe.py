"""Probe di capability kernel all'avvio (M3 Fase 4).

Determina il profilo sensore Linux — FULL (eBPF completo), PARTIAL (BTF o
caps mancanti), ABSENT (niente eBPF) — con fallback dichiarati. Parser puri
(versioni/capability) testabili ovunque; probe live solo su Linux, mai
eccezioni: in caso di dubbio il profilo è ABSENT con motivo.
"""
import os
import platform
import re

FULL = "full"
PARTIAL = "partial"
ABSENT = "absent"
UNAVAILABLE = "unavailable"


def sensor_mode(platform_system: str, ebpf_on: bool, auditd_on: bool) -> str:
    """Modalità sensore effettiva (Fase 3): full > partial > fallback > unavailable.

    Puro e testabile: l'agent la calcola dai flag reali e la pubblica in
    capabilities + heartbeat così il SOC vede il degrado.
    """
    plat = (platform_system or "").lower()
    if "linux" not in plat:
        return UNAVAILABLE
    if ebpf_on:
        return FULL
    if auditd_on:
        return PARTIAL
    return "fallback"


def parse_kernel_release(release: str) -> tuple:
    """'6.6.8-200.fc39' -> (6, 6, 8). Tupla vuota se illeggibile."""
    try:
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", (release or "").strip())
        if not m:
            return ()
        return tuple(int(g) for g in m.groups() if g is not None)
    except (TypeError, ValueError):
        return ()


def kernel_supports_ebpf(release: str) -> bool:
    """eBPF CO-RE utilizzabile da kernel >= 5.8 (requisito documentato)."""
    v = parse_kernel_release(release)
    return len(v) >= 2 and (v[0], v[1]) >= (5, 8)


def parse_cap_eff(status_content: str) -> int:
    """Estrae CapEff da /proc/self/status. -1 se illeggibile."""
    try:
        for line in (status_content or "").splitlines():
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
    except (IndexError, ValueError):
        pass
    return -1


# CAP_BPF=39, CAP_PERFMON=38 (linux/capability.h). Audit utile anche senza.
CAP_BPF = 1 << 39
CAP_PERFMON = 1 << 38
CAP_SYS_ADMIN = 1 << 21


def has_ebpf_caps(cap_eff: int) -> bool:
    if cap_eff < 0:
        return False
    if cap_eff & CAP_SYS_ADMIN:
        return True  # root pieno / --privileged
    return bool((cap_eff & CAP_BPF) and (cap_eff & CAP_PERFMON))


def probe(btf_path: str = "/sys/kernel/btf/vmlinux") -> dict:
    """Profilo sensore live. Mai eccezioni: fallback ABSENT con motivo."""
    try:
        if platform.system() != "Linux":
            return {"profile": ABSENT, "reason": "not-linux", "kernel": platform.release()}
        release = platform.release()
        kernel_ok = kernel_supports_ebpf(release)
        btf_ok = os.path.exists(btf_path)
        try:
            with open("/proc/self/status", encoding="utf-8", errors="replace") as f:
                cap_eff = parse_cap_eff(f.read())
        except OSError:
            cap_eff = -1
        caps_ok = has_ebpf_caps(cap_eff)
        if kernel_ok and btf_ok and caps_ok:
            return {"profile": FULL, "reason": "",
                    "kernel": release, "btf": True, "caps": True}
        reasons = []
        if not kernel_ok:
            reasons.append(f"kernel-{release}-too-old")
        if not btf_ok:
            reasons.append("no-btf")
        if not caps_ok:
            reasons.append("no-caps")
        profile = PARTIAL if (kernel_ok and (btf_ok or caps_ok)) else ABSENT
        return {"profile": profile, "reason": "+".join(reasons),
                "kernel": release, "btf": btf_ok, "caps": caps_ok}
    except Exception as e:  # pragma: no cover - difesa
        return {"profile": ABSENT, "reason": f"probe-error:{e}"}


def auditd_available(paths=("/var/log/audit/audit.log",)) -> str:
    """Ritorna il primo log auditd leggibile, o '' (fallback non disponibile)."""
    try:
        for p in paths:
            if os.path.isfile(p) and os.access(p, os.R_OK):
                return p
    except Exception:
        pass
    return ""


def systemd_available() -> bool:
    try:
        return os.path.isdir("/run/systemd/system")
    except Exception:
        return False
