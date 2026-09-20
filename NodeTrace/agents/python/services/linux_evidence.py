"""Evidenza read-only endpoint Linux (Fase 3, Tier-3 dichiarati come Windows).
Raccoglie SOLO metadati (nomi, path, permessi, hash), MAI contenuti:
systemd unit, cron, SSH authorized_keys (impronte), shell profile, moduli
kernel, capabilities, cgroup/namespace/container, secret-file (permessi).
Ogni sorgente fallisce soft con motivo degraded. Parser puri testabili
ovunque; i live collector girano solo su Linux.
"""
import base64
import hashlib
import os

SYSTEMD_DIRS = ("/etc/systemd/system", "/run/systemd/system",
                "/usr/lib/systemd/system", "/lib/systemd/system")
CRON_PATHS = ("/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
              "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
              "/var/spool/cron", "/var/spool/cron/crontabs")
PROFILE_FILES = ("/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc")
USER_PROFILE_NAMES = (".bashrc", ".bash_profile", ".profile", ".zshrc")
SSH_NAMES = ("authorized_keys", "authorized_keys2")
SECRET_PATHS = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers",
                "/etc/sudoers.d", "/root/.ssh", "/etc/ssl/private",
                "/etc/kubernetes", "/etc/docker", "/var/lib/kubelet")
CAP_NAMES = {
    0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER",
    4: "FSETID", 5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP",
    9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_ADMIN",
    12: "NET_RAW", 13: "IPC_LOCK", 14: "IPC_OWNER", 15: "SYS_MODULE",
    16: "SYS_RAWIO", 17: "SYS_CHROOT", 18: "SYS_PTRACE", 19: "SYS_PACCT",
    20: "SYS_ADMIN", 21: "SYS_BOOT", 22: "SYS_NICE", 23: "SYS_RESOURCE",
    24: "SYS_TIME", 25: "SYS_TTY_CONFIG", 26: "MKNOD", 27: "LEASE",
    28: "AUDIT_WRITE", 29: "AUDIT_CONTROL", 30: "SETFCAP", 31: "MAC_OVERRIDE",
    32: "MAC_ADMIN", 33: "SYSLOG", 34: "WAKE_ALARM", 35: "BLOCK_SUSPEND",
    36: "AUDIT_READ", 37: "PERFMON", 38: "BPF", 39: "CHECKPOINT_RESTORE",
}


def decode_caps(mask: int) -> list:
    """Bitmask CapEff -> nomi (puro)."""
    try:
        mask = int(mask)
    except (TypeError, ValueError):
        return []
    if mask < 0:
        return []
    return [CAP_NAMES[b] for b in range(64) if (mask >> b) & 1 and b in CAP_NAMES]


def parse_cap_eff(status_content: str) -> int:
    try:
        for line in (status_content or "").splitlines():
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
    except (IndexError, ValueError):
        pass
    return -1


def file_meta(path: str) -> dict | None:
    """Metadati senza contenuto: size, mode, uid, sha256 del PATH (non del file!)."""
    try:
        st = os.stat(path)
        return {"path": path, "size": st.st_size,
                "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid}
    except OSError:
        return None


def list_unit_files(dirs=SYSTEMD_DIRS) -> list:
    """Nomi unit .service/.timer/.socket presenti (puro su lista dir)."""
    out = []
    for d in dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if n.endswith((".service", ".timer", ".socket", ".path")):
                out.append({"name": n, "dir": d,
                            "meta": file_meta(os.path.join(d, n))})
    return out


def list_cron_entries(paths=CRON_PATHS) -> list:
    """File/dir cron esistenti con metadati (mai contenuti dei job)."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            try:
                children = sorted(os.listdir(p))
            except OSError:
                continue
            out.append({"path": p, "type": "dir", "entries": len(children),
                        "meta": file_meta(p)})
        elif os.path.isfile(p) or os.path.islink(p):
            out.append({"path": p, "type": "file", "meta": file_meta(p)})
    return out


def ssh_key_fingerprints(authorized_keys_path: str) -> list:
    """Impronte SHA256 delle chiavi (mai le chiavi). Puro sul contenuto."""
    fps = []
    try:
        with open(authorized_keys_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return fps
    return parse_authorized_keys(content)


def parse_authorized_keys(content: str) -> list:
    """Righe 'algo base64 commento' -> [{algo, sha256, comment}]. Puro."""
    out = []
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        algo, blob = parts[0], parts[1]
        if algo.startswith("sk-"):
            algo = algo[3:]
        if algo not in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256",
                        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                        "ssh-dss", "ssh-ed25519-cert-v01@openssh.com",
                        "ssh-rsa-cert-v01@openssh.com"):
            continue
        try:
            # padding mancante comune nei campioni sintetici
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        digest = hashlib.sha256(raw).hexdigest()
        out.append({"algo": algo, "sha256": digest,
                    "comment": parts[2] if len(parts) > 2 else ""})
    return out


def parse_lsmod(content: str) -> list:
    """Righe 'modulo size usedby' -> nomi (puro)."""
    out = []
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Module"):
            continue
        parts = line.split()
        if parts:
            out.append(parts[0])
    return out


def container_hint(cgroup_content: str = "", sched_content: str = "") -> dict:
    """Rileva container runtime da /proc/1/cgroup e /proc/1/sched (puro).

    Ritorna {"container": bool, "runtime": "docker"|"podman"|"kubepods"|"lxc"|""}.
    """
    text = f"{cgroup_content}\n{sched_content}".lower()
    for runtime in ("kubepods", "docker", "podman", "lxc", "containerd", "crio"):
        if runtime in text:
            return {"container": True, "runtime": runtime}
    # PID 1 non-systemd fuori container init = indizio debole, non prova.
    return {"container": False, "runtime": ""}


def collect() -> dict:
    """Snapshot completo best-effort. Mai eccezioni, mai contenuti."""
    import platform
    ev = {"degraded": [], "os": platform.system()}
    if platform.system() != "Linux":
        ev["degraded"].append("not-linux")
        return ev

    def attempt(name, fn):
        try:
            return fn()
        except Exception as e:
            ev["degraded"].append(f"{name}:{e.__class__.__name__}")
            return None

    units = attempt("systemd", list_unit_files)
    ev["units"] = units if units is not None else []
    ev["unit_count"] = len(ev["units"])
    cron = attempt("cron", list_cron_entries)
    ev["cron"] = cron if cron is not None else []
    profiles = []
    for p in PROFILE_FILES:
        m = file_meta(p)
        if m:
            profiles.append(m)
    home = os.path.expanduser("~")
    for n in USER_PROFILE_NAMES:
        m = file_meta(os.path.join(home, n))
        if m:
            profiles.append(m)
    ev["profiles"] = profiles
    keys = []
    for ssh_dir in (os.path.join(home, ".ssh"), "/root/.ssh", "/etc/ssh"):
        for kn in SSH_NAMES:
            kp = os.path.join(ssh_dir, kn)
            if os.path.isfile(kp):
                keys.append({"path": kp, "meta": file_meta(kp),
                             "fingerprints": ssh_key_fingerprints(kp)})
    ev["ssh_keys"] = keys
    try:
        with open("/proc/modules", encoding="utf-8", errors="replace") as f:
            mods = parse_lsmod(f.read())
        ev["kernel_modules"] = mods
        ev["kernel_module_count"] = len(mods)
    except OSError:
        ev["degraded"].append("modules:unreadable")
        ev["kernel_modules"] = []
    try:
        with open("/proc/self/status", encoding="utf-8", errors="replace") as f:
            cap_eff = parse_cap_eff(f.read())
        ev["cap_eff"] = hex(cap_eff) if cap_eff >= 0 else None
        ev["capabilities"] = decode_caps(cap_eff)
    except OSError:
        ev["degraded"].append("caps:unreadable")
        ev["capabilities"] = []
    for src, dst in (("/proc/1/cgroup", "cgroup"), ("/proc/1/sched", "sched")):
        try:
            with open(src, encoding="utf-8", errors="replace") as f:
                ev[dst] = f.read(4096)
        except OSError:
            ev[dst] = ""
    ev.update(container_hint(ev.get("cgroup", ""), ev.get("sched", "")))
    ev.pop("cgroup", None)
    ev.pop("sched", None)
    secrets = []
    for p in SECRET_PATHS:
        m = file_meta(p)
        if m:
            m["world_readable"] = bool(int(m["mode"], 8) & 0o044)
            secrets.append(m)
    ev["secrets"] = secrets
    return ev
