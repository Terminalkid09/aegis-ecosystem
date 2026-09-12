"""Fallback auditd mirato (M3 Fase 4): solo exec, mai duplicatore indiscriminato.

Quando eBPF è ABSENT ma auditd gira, questo parser estrae eventi exec dai
record SYSCALL+EXECVE e li mappa al contratto unico v2 (provenance
'auditd'). I filtri stanno qui: SYSCALL success=yes + arch/execve-like;
tutto il resto viene scartato prima ancora di costruire l'evento.

Formato atteso (ausearch --raw / audit.log):
  type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59
    success=yes ... pid=101 ppid=100 auid=1000 uid=1000 ... exe="/bin/bash"
  type=EXECVE msg=audit(1700000000.123:456): argc=2 a0="bash" a1="-c"
"""
import re
import uuid

EXEC_SYSCALLS = {"59", "execve", "322", "execveat"}

_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _kvs(line: str) -> dict:
    out = {}
    try:
        for k, v in _KV.findall(line or ""):
            out[k] = v.strip('"')
    except Exception:
        pass
    return out


def parse_record(lines: list) -> dict | None:
    """Un record (righe SYSCALL+EXECVE). Ritorna evento v2 o None (scarto)."""
    if not lines:
        return None
    joined = "\n".join(lines)
    if "type=SYSCALL" not in joined:
        return None
    syscalls = [ln for ln in lines if "type=SYSCALL" in ln]
    if not syscalls:
        return None
    kv = _kvs(syscalls[0])
    if kv.get("success") != "yes":
        return None
    if kv.get("syscall") not in EXEC_SYSCALLS and "execve" not in kv.get("syscall", ""):
        return None
    try:
        pid = int(kv.get("pid", 0))
    except (TypeError, ValueError):
        return None
    if pid < 1:
        return None
    try:
        ppid = int(kv.get("ppid", 0) or 0)
    except (TypeError, ValueError):
        ppid = 0
    try:
        uid = int(kv.get("uid", kv.get("auid", 0)) or 0)
    except (TypeError, ValueError):
        uid = 0
    # Comm: a0 dell'EXECVE se presente, altrimenti basename di exe.
    comm = ""
    for ln in lines:
        if "type=EXECVE" in ln:
            ekv = _kvs(ln)
            if ekv.get("a0"):
                comm = ekv["a0"].split("/")[-1]
                break
    exe = kv.get("exe", "")
    if not comm:
        comm = (exe or "unknown").split("/")[-1] or "unknown"
    try:
        m = re.search(r"audit\((\d+\.\d+):", syscalls[0])
        ts_ns = int(float(m.group(1)) * 1e9) if m else 0
    except (TypeError, ValueError):
        ts_ns = 0
    return {
        "schema_version": 2,
        "event_id": str(uuid.uuid4()),
        "pid": pid,
        "ppid": ppid,
        "uid": max(uid, 0),
        "comm": comm,
        "filename": exe,
        "event_type": "PROCESS_CREATED",
        "ts_wall_ns": ts_ns if ts_ns > 0 else None,
        "provenance": "auditd",
        "quality": "full",
    }


class AuditdTailer:
    """Coda record da un file audit.log (segue append, tollera rotation)."""

    def __init__(self, path: str):
        self.path = path
        self._offset = 0

    def poll(self) -> list:
        """Ritorna gli eventi exec nuovi dall'ultima poll. Mai eccezioni."""
        events = []
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                chunk = f.read(1 << 20)  # 1 MB per poll, tetto anti-storm
                self._offset = f.tell()
        except (OSError, ValueError):
            try:
                self._offset = 0  # rotation: riparti dall'inizio
            except Exception:
                pass
            return events
        record = []
        for line in chunk.splitlines():
            if line.startswith("type=") and record and "type=SYSCALL" in record[0]:
                ev = parse_record(record)
                if ev:
                    events.append(ev)
                record = [line]
            else:
                record.append(line)
        if record:
            ev = parse_record(record)
            if ev:
                events.append(ev)
        return events
