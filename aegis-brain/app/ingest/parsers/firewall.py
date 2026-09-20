"""Parser dei log firewall: pfSense filterlog, iptables/ufw, Windows Firewall.

Un firewall rivela scan, tentativi bloccati e movimento laterale. Tre formati
coprono quasi tutto:
- **pfSense/OPNsense filterlog** (CSV),
- **iptables/ufw** (log kernel `IN=… OUT=… SRC=… DST=… PROTO=…`),
- **Windows Firewall** `pfirewall.log` — l'unico ottenibile direttamente su un
  PC Windows di sviluppo, quindi REALE in questo lab.

Le azioni `block`/`DROP` sono normalizzate in `event_type=network_denied` con
severità MEDIUM: è il segnale grezzo su cui la correlazione costruisce
`port_sweep` (molte destinazioni bloccate dallo stesso mittente in poco tempo).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_protocol, parse_timestamp,
)

# iptables/ufw: coppie CHIAVE=valore nel messaggio kernel.
_KV = re.compile(r"([A-Z_]+)=((?:\"[^\"]*\")|\S+)")
_IPTABLES = re.compile(r"(?:\bIN=\S*|\bSRC=)\s+.*\bDST=\S+")

# pfSense filterlog CSV: almeno 20 colonne, azione in posizione 6.
_PFSENSE_MIN_COLS = 18

# Windows Firewall: data, ora, azione, proto, src, dst, sport, dport, size, …, dir
_PFIREWALL = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>[A-Z]+)\s+(?P<proto>[A-Z]+)\s+"
    r"(?P<src_ip>\S+)\s+(?P<dst_ip>\S+)\s+(?P<src_port>\d+|-)\s+(?P<dst_port>\d+|-)\s+"
    r"(?P<size>\d+|-)\s+(?P<rest>.*)$"
)

_BLOCK = ("block", "drop", "deny", "reject", "closed")

# Timestamp RFC3164, anche preceduto dal PRI syslog (`<134>Sep 15 …`): i log
# firewall arrivano quasi sempre inoltrati via syslog.
_SYSLOG_TS = re.compile(r"(?:<\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)")
_SYSLOG_TS_ONLY = re.compile(r"(?:<\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")


class FirewallParser:
    source_type = "firewall"

    def __init__(self, name: str = "firewall"):
        self.name = name

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        if isinstance(payload, dict):
            return False
        line = (payload if isinstance(payload, str) else "")
        for candidate in line.splitlines():
            candidate = candidate.strip()
            if not candidate:
                continue
            detected = self._detect(candidate)
            # Un parser registrato per un formato specifico accetta SOLO quello:
            # altrimenti l'attribuzione (e la diagnostica) mentirebbe.
            if self.name in ("pfsense", "pfirewall", "iptables"):
                return detected == self.name
            return bool(detected)
        return False

    @staticmethod
    def _detect(line: str) -> Optional[str]:
        if _PFIREWALL.match(line):
            return "pfirewall"
        if _IPTABLES.search(line) and "DST=" in line:
            return "iptables"
        if line.count(",") >= _PFSENSE_MIN_COLS:
            cols = line.split(",")
            if len(cols) >= 8 and cols[6].strip().lower() in _BLOCK + ("pass",):
                return "pfsense"
        return None

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        if not isinstance(payload, str):
            raise ParserError("firewall log must be text")
        source = meta.get("source") or self.name
        fallback_ts = parse_timestamp(meta.get("received_at"))
        events: List[UnifiedEvent] = []
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            # Se il parser è registrato per un formato specifico, quello è il
            # default; altrimenti si accetta solo ciò che viene riconosciuto.
            fmt = self._detect(line)
            if fmt is None and self.name in ("pfsense", "pfirewall", "iptables"):
                fmt = self.name
            if fmt is None:
                continue
            handler = {"pfirewall": self._pfirewall, "iptables": self._iptables,
                       "pfsense": self._pfsense}[fmt]
            event = handler(line, source, fallback_ts, fmt)
            if event is not None:
                events.append(event)
        if not events:
            raise ParserError("no parseable firewall line")
        return events

    # ── Windows Firewall ────────────────────────────────────────────────────
    def _pfirewall(self, line: str, source: str, fallback_ts, fmt: str) -> Optional[UnifiedEvent]:
        m = _PFIREWALL.match(line)
        if not m:
            return None
        g = m.groupdict()
        blocked = g["action"].lower() in _BLOCK
        rest = (g.get("rest") or "").split()
        direction = rest[-1] if rest else None
        ts = parse_timestamp(f"{g['date']}T{g['time']}", default=fallback_ts)
        return finalize(UnifiedEvent(
            time=ts,
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            ocsf_class_uid=4001,
            severity="MEDIUM" if blocked else "INFO",
            ip=g["src_ip"],
            src_ip=g["src_ip"],
            src_port=as_int(g["src_port"]),
            dst_ip=g["dst_ip"],
            dst_port=as_int(g["dst_port"]),
            protocol=normalize_protocol(g["proto"]),
            extra={"action": g["action"].lower(), "direction": direction,
                   "format": fmt, "bytes": as_int(g["size"]),
                   "event_type": "network_denied" if blocked else "network_allow"},
            message=f"{g['action']} {g['proto']} {g['src_ip']}:{g['src_port']} -> "
                    f"{g['dst_ip']}:{g['dst_port']}",
            raw=bounded_raw(line),
        ))

    # ── iptables / ufw ──────────────────────────────────────────────────────
    def _iptables(self, line: str, source: str, fallback_ts, fmt: str) -> Optional[UnifiedEvent]:
        fields = {k: v.strip('"') for k, v in _KV.findall(line)}
        src, dst = fields.get("SRC"), fields.get("DST")
        if not src or not dst:
            return None
        # Il prefisso syslog (se presente) fornisce il timestamp e l'host.
        ts_match = _SYSLOG_TS.search(line)
        blocked = bool(re.search(r"(?i)\b(dpt|block|drop|deny)\b", line)) and \
            not re.search(r"(?i)\b(accept|allow)\b", line)
        return finalize(UnifiedEvent(
            time=parse_timestamp(ts_match.group("ts") if ts_match else None, default=fallback_ts),
            hostname=ts_match.group("host") if ts_match else None,
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            ocsf_class_uid=4001,
            severity="MEDIUM" if blocked else "INFO",
            ip=src,
            src_ip=src,
            src_port=as_int(fields.get("SPT")),
            dst_ip=dst,
            dst_port=as_int(fields.get("DPT")),
            protocol=normalize_protocol(fields.get("PROTO")),
            extra={"in_iface": fields.get("IN"), "out_iface": fields.get("OUT"),
                   "ttl": as_int(fields.get("TTL")), "format": fmt,
                   "event_type": "network_denied" if blocked else "network_allow"},
            message=line[-500:],
            raw=bounded_raw(line),
        ))

    # ── pfSense / OPNsense filterlog ────────────────────────────────────────
    def _pfsense(self, line: str, source: str, fallback_ts, fmt: str) -> Optional[UnifiedEvent]:
        # Il messaggio syslog può precedere il CSV: si parte dal primo campo numerico.
        csv_start = re.search(r"(?<![\d,])(\d+)(?=,)", line)
        body = line[csv_start.start():] if csv_start else line
        # Verifica che il CSV non contenga il prefisso syslog: normalizza.
        if body.count(",") < _PFSENSE_MIN_COLS:
            _, _, body = line.partition("filterlog: ")
        cols = [c.strip() for c in body.split(",")]
        if len(cols) < _PFSENSE_MIN_COLS:
            return None
        ts_match = _SYSLOG_TS.search(line)
        action = cols[6].lower()
        direction = cols[7].lower() if len(cols) > 7 else None
        proto = cols[16] if len(cols) > 16 else None
        src_ip = cols[18] if len(cols) > 18 else None
        dst_ip = cols[19] if len(cols) > 19 else None
        if not src_ip or not dst_ip:
            return None
        blocked = action in _BLOCK
        return finalize(UnifiedEvent(
            time=parse_timestamp(ts_match.group("ts") if ts_match else None, default=fallback_ts),
            hostname=ts_match.group("host") if ts_match else None,
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            ocsf_class_uid=4001,
            severity="MEDIUM" if blocked else "INFO",
            ip=src_ip,
            src_ip=src_ip,
            src_port=as_int(cols[20]) if len(cols) > 20 else None,
            dst_ip=dst_ip,
            dst_port=as_int(cols[21]) if len(cols) > 21 else None,
            protocol=normalize_protocol(proto),
            extra={"action": action, "direction": direction,
                   "interface": cols[4] if len(cols) > 4 else None,
                   "ip_version": as_int(cols[8]) if len(cols) > 8 else None,
                   "format": fmt,
                   "event_type": "network_denied" if blocked else "network_allow"},
            message=f"{action} {proto} {src_ip} -> {dst_ip}",
            raw=bounded_raw(line),
        ))
