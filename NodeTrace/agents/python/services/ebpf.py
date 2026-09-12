"""Forward eventi kernel (contratto unico) al brain come PROCESS_CREATED/EXITED.

Il collector eBPF gira come sottoprocesso (solo Linux, root/CAP_BPF);
questo modulo ne legge lo stdout riga per riga e mappa ogni evento nel
payload EventSchema atteso da POST /telemetry/report.

Mappa pura in event_to_report() — testata in tests/test_ebpf.py senza
sottoprocessi né rete.
"""
import json
import os
import uuid
from datetime import datetime, timezone

TYPES = ("PROCESS_CREATED", "PROCESS_EXITED", "CONNECTION_ESTABLISHED")

# Campi v2 passati invariati al brain quando il collector li fornisce.
# Tutto opzionale: le righe legacy v1 restano valide.
V2_PASSTHROUGH = (
    "boot_id", "session", "integrity", "proto", "direction",
    "container_id", "cgroup", "namespace", "provenance", "quality",
    "sampling", "signature", "publisher",
)
V2_INT_FIELDS = ("seq", "ts_wall_ns", "proc_start_ns")


def parse_line(line: str):
    """Parsa una riga del collector. Ritorna dict o None se non valida."""
    if not line or not line.strip():
        return None
    try:
        ev = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(ev, dict):
        return None
    if ev.get("event_type") not in TYPES:
        return None
    try:
        pid = int(ev.get("pid", 0))
    except (TypeError, ValueError):
        return None
    if pid < 1:
        return None
    return ev


def event_to_report(ev: dict, device_id: str, hostname=None, ip_local=None,
                    agent_version=None, default_provenance: str | None = None) -> dict:
    """Mappa evento kernel -> payload EventSchema per /telemetry/report.

    CONNECTION_ESTABLISHED viaggia con network_connections così il brain
    la passa alla beacon correlation (stesso formato di netstat/ss).
    default_provenance (es. 'ebpf-full') timbra solo eventi che non
    dichiarano già una provenienza.
    """
    if ev.get("event_type") == "CONNECTION_ESTABLISHED":
        remote = str(ev.get("remote") or "")
        prov = ev.get("provenance") or default_provenance
        return {
            "agent_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "CONNECTION_ESTABLISHED",
            "event_id": str(ev.get("event_id") or uuid.uuid4()),
            "schema_version": int(ev.get("schema_version") or 2),
            "pid": int(ev.get("pid", 0) or 0),
            "process_name": str(ev.get("comm") or "unknown"),
            "hostname": hostname,
            "ip_address": ip_local,
            "agent_version": agent_version,
            "ts_monotonic_ns": ev.get("ts_ns"),
            **_v2_extra(ev),
            "provenance": prov,
            "network_connections": [{"remote": remote, "state": "ESTABLISHED"}] if remote else [],
        }
    try:
        ppid = int(ev.get("ppid", 0) or 0)
    except (TypeError, ValueError):
        ppid = 0
    comm = str(ev.get("comm") or "unknown")
    filename = str(ev.get("filename") or "")
    prov = ev.get("provenance") or default_provenance
    return {
        "agent_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": ev["event_type"],
        "event_id": str(ev.get("event_id") or uuid.uuid4()),
        "schema_version": int(ev.get("schema_version") or 2),
        "pid": int(ev["pid"]),
        "parent_pid": ppid if ppid > 0 else None,
        "process_name": comm,
        "process_path": filename or None,
        "hostname": hostname,
        "ip_address": ip_local,
        "agent_version": agent_version,
        "ts_monotonic_ns": ev.get("ts_ns"),
        **_v2_extra(ev),
        "provenance": prov,
    }


def _v2_extra(ev: dict) -> dict:
    """Campi v2 opzionali passati al brain solo se presenti e ben tipati."""
    out = {}
    for k in V2_PASSTHROUGH:
        v = ev.get(k)
        if isinstance(v, str) and v:
            out[k] = v
    for k in V2_INT_FIELDS:
        v = ev.get(k)
        try:
            if v is not None:
                iv = int(v)
                if iv >= 0:
                    out[k] = iv
        except (TypeError, ValueError):
            continue
    return out


def collector_cmd(collector_path: str, obj_path: str | None = None) -> list:
    cmd = [collector_path]
    if obj_path:
        cmd += ["--obj", obj_path]
    cmd += ["--exclude-pid", str(os.getpid())]
    return cmd


class KernelEventBatcher:
    """Accumula report e scarica a soglia (N eventi o T secondi).

    Sotto storm di exec evita un POST per evento. Tempi iniettabili per i test.
    M1 Fase 2: bound anti-OOM — oltre max_items scarta i più vecchi CONTANDOLI
    (backpressure visibile, mai perdita invisibile).
    """

    def __init__(self, max_n: int = 25, max_age_s: float = 2.0, max_items: int = 2000):
        self.max_n = max_n
        self.max_age_s = max_age_s
        self.max_items = max_items
        self._items: list = []
        self._first_ts: float | None = None
        self.received = 0
        self.drained = 0
        self.dropped = 0

    def add(self, report: dict, now_s: float | None = None) -> bool:
        import time as _time
        now = now_s if now_s is not None else _time.time()
        if self._first_ts is None:
            self._first_ts = now
        self._items.append(report)
        self.received += 1
        while len(self._items) > self.max_items:
            self._items.pop(0)
            self.dropped += 1
        return self.due(now_s=now)

    def due(self, now_s: float | None = None) -> bool:
        import time as _time
        if not self._items:
            return False
        if len(self._items) >= self.max_n:
            return True
        now = now_s if now_s is not None else _time.time()
        return (now - (self._first_ts or now)) >= self.max_age_s

    def drain(self) -> list:
        out = self._items
        self._items = []
        self._first_ts = None
        self.drained += len(out)
        return out

    def stats(self) -> dict:
        return {
            "received": self.received,
            "drained": self.drained,
            "dropped": self.dropped,
            "buffered": len(self._items),
        }

    def __len__(self) -> int:
        return len(self._items)


class SeenCache:
    """Dedup finestrata per eventi kernel (Fase 3): eBPF e auditd possono
    osservare lo stesso exec (overlap sorgenti, restart collector).

    Chiave (pid, ppid, comm, event_type), finestra 5 s di default: duplicati
    scartati e CONTATI. Tempi iniettabili, niente I/O, thread-unsafe per
    design (un thread per stream).
    """

    def __init__(self, window_s: float = 5.0, max_keys: int = 10000):
        self.window_s = window_s
        self.max_keys = max_keys
        self._seen: dict = {}
        self.duplicates = 0

    def check(self, ev: dict, now_s: float | None = None) -> bool:
        """True se duplicato (da scartare), False se nuovo."""
        import time as _time
        now = now_s if now_s is not None else _time.time()
        if not isinstance(ev, dict):
            return False
        try:
            key = (int(ev.get("pid", 0)), int(ev.get("ppid", 0) or 0),
                   str(ev.get("comm") or ev.get("process_name") or ""),
                   str(ev.get("event_type") or ""))
        except (TypeError, ValueError):
            return False
        # Scadenza pigra: pulizia completa solo oltre il tetto (O(1) ammortizzato).
        if len(self._seen) >= self.max_keys:
            cutoff = now - self.window_s
            self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}
        last = self._seen.get(key)
        if last is not None and (now - last) < self.window_s:
            self.duplicates += 1
            return True
        self._seen[key] = now
        return False
