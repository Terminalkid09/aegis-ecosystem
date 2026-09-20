"""Parser dei log Zeek (conn/dns/http/ssl/files/notice), TSV e JSON.

Zeek (ex Bro) è lo standard de-facto per la telemetria di rete nei SOC: non è
un IDS, produce log strutturati per flusso, DNS, HTTP, TLS. Ingerirli dà
visibilità di rete senza scrivere un sensore.

Due formati reali:
- **TSV** con header `#separator`/`#set_separator`/`#fields`/`#types`/`#path`,
- **JSON** (`Zeek JSON output`, una riga per record: `id.orig_h`, `query`, …).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_protocol, normalize_severity, parse_timestamp,
)

_Z = "\x09"  # separatore Zeek
# Campi comuni presenti nei log Zeek (usati anche per l'auto-detection JSON).
_ZEEK_KEYS = {"id.orig_h", "id.resp_h", "uid", "conn_state", "proto", "query",
              "qtype_name", "method", "status_code", "server_name", "trans_id"}

_PATH_TO_CATEGORY = {
    "conn": "network", "dns": "network", "http": "web", "ssl": "network",
    "files": "file", "notice": "detection", "weird": "anomaly",
    "ssh": "authentication", "dhcp": "network", "smtp": "email",
    "smb_files": "file", "kerberos": "authentication", "pe": "file",
}


def _to_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _unset(value: str) -> Optional[str]:
    return None if value in ("", "-", "(empty)", "(unset)") else value


class ZeekParser:
    name = "zeek"
    source_type = "zeek"

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        if isinstance(payload, dict):
            return bool(_ZEEK_KEYS & set(payload.keys()))
        if not isinstance(payload, str):
            return False
        text = payload.lstrip()
        if text.startswith("#separator") or text.startswith("#fields"):
            return True
        if text.startswith("#"):  # header Zeek senza #separator (raro)
            return "#fields" in text
        first = text.splitlines()[0] if text.splitlines() else ""
        if first.strip().startswith("{"):
            try:
                obj = json.loads(first)
            except json.JSONDecodeError:
                return False
            return isinstance(obj, dict) and bool(_ZEEK_KEYS & set(obj.keys()))
        return False

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        if isinstance(payload, (dict, list)):
            return self._parse_json(payload, meta)
        if not isinstance(payload, str):
            raise ParserError("unsupported Zeek payload type")
        text = payload
        if text.lstrip().startswith("{"):
            return self._parse_json(text, meta)
        return self._parse_tsv(text, meta)

    # ── JSON ────────────────────────────────────────────────────────────────
    def _parse_json(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        source = meta.get("source") or "zeek"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        records: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            records = [payload]
        elif isinstance(payload, list):
            records = [r for r in payload if isinstance(r, dict)]
        else:
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    records.append(obj)
        if not records:
            raise ParserError("no Zeek JSON record")
        return [self._from_fields(r, r.get("_path") or self._guess_path(r),
                                  source, fallback_ts, raw=r) for r in records]

    @staticmethod
    def _guess_path(record: Dict[str, Any]) -> str:
        if "conn_state" in record or "id.orig_h" in record and "duration" in record:
            return "conn"
        if "query" in record:
            return "dns"
        if "method" in record or "status_code" in record:
            return "http"
        if "server_name" in record or "cipher" in record:
            return "ssl"
        if "note" in record:
            return "notice"
        return "unknown"

    # ── TSV ─────────────────────────────────────────────────────────────────
    def _parse_tsv(self, text: str, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        source = meta.get("source") or "zeek"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        fields: Optional[List[str]] = None
        path = "unknown"
        separator = _Z
        set_separator = ","
        lines: List[str] = []
        for raw_line in text.splitlines():
            if not raw_line:
                continue
            if raw_line.startswith("#"):
                if raw_line.startswith("#separator"):
                    sep = raw_line.split(" ", 1)[1] if " " in raw_line else ""
                    separator = {"\\x09": _Z, "\\x20": " ", "\\x2c": ","}.get(sep, sep or _Z)
                elif raw_line.startswith("#set_separator"):
                    set_separator = raw_line.split(" ", 1)[1] if " " in raw_line else ","
                elif raw_line.startswith("#fields"):
                    fields = raw_line.split(separator)[1:]
                elif raw_line.startswith("#path"):
                    path = raw_line.split(separator, 1)[-1].strip()
                continue
            lines.append(raw_line)
        if fields is None:
            raise ParserError("Zeek TSV without #fields header")
        if path == "unknown":
            # Molti file Zeek hanno `#path`, ma non tutti gli export: si deduce
            # dalla presenza di campi caratteristici invece di etichettare tutto
            # come "unknown".
            keys = set(fields)
            if "conn_state" in keys or "orig_bytes" in keys:
                path = "conn"
            elif "query" in keys:
                path = "dns"
            elif "method" in keys or "status_code" in keys:
                path = "http"
            elif "server_name" in keys or "cipher" in keys:
                path = "ssl"
            elif "note" in keys:
                path = "notice"
            elif "fuid" in keys:
                path = "files"
        events: List[UnifiedEvent] = []
        for line in lines:
            values = line.split(separator)
            if len(values) < 2:
                continue
            record = {name: _unset(values[i]) for i, name in enumerate(fields) if i < len(values)}
            if "ts" in record:
                record["ts"] = record["ts"]
            events.append(self._from_fields(record, path, source, fallback_ts,
                                            raw=line, set_separator=set_separator))
        if not events:
            raise ParserError("Zeek TSV with header but no data rows")
        return events

    # ── record → UnifiedEvent ───────────────────────────────────────────────
    def _from_fields(self, r: Dict[str, Any], path: str, source: str,
                     fallback_ts, raw: Any, set_separator: str = ",") -> UnifiedEvent:
        extra: Dict[str, Any] = {"zeek_log": path}
        for key in ("uid", "community_id", "service", "conn_state", "duration",
                    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "qtype_name",
                    "rcode_name", "answers", "version", "cipher", "ja3", "note",
                    "msg", "sub", "peer", "trans_depth", "referrer", "mime_type",
                    "pe_info", "ts"):
            if r.get(key) not in (None, ""):
                extra[key] = r[key]

        answers = r.get("answers")
        if isinstance(answers, list) and answers:
            extra["answers"] = ",".join(map(str, answers))[:500]

        # notice.log: la `note` di Zeek è la detection, con priorità propria.
        severity = "INFO"
        signature = None
        if path == "notice":
            signature = r.get("note")
            priority = str(r.get("priority", "") or "").lower()
            severity = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM",
                        "4": "LOW", "5": "INFO"}.get(priority, "MEDIUM")
            severity = normalize_severity(r.get("severity") or severity)

        proto = normalize_protocol(r.get("proto"))
        return finalize(UnifiedEvent(
            time=parse_timestamp(r.get("ts"), default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, raw),
            ocsf_class_uid={"dns": 4003, "http": 4002, "conn": 4001,
                            "ssl": 4001, "notice": 2004}.get(path, 0),
            severity=severity,
            hostname=_unset(str(r.get("host") or r.get("machine") or "")) or None,
            ip=_unset(str(r.get("id.orig_h") or "")) or None,
            user=_unset(str(r.get("user") or r.get("username") or "")) or None,
            src_ip=_unset(str(r.get("id.orig_h") or "")) or None,
            src_port=as_int(r.get("id.orig_p")),
            dst_ip=_unset(str(r.get("id.resp_h") or "")) or None,
            dst_port=as_int(r.get("id.resp_p")),
            protocol=proto,
            url=str(r.get("uri"))[:2000] if r.get("uri") else None,
            http_method=_unset(str(r.get("method") or "")) or None,
            http_status=as_int(r.get("status_code")),
            user_agent=str(r.get("user_agent"))[:1000] if r.get("user_agent") else None,
            domain=_unset(str(r.get("host") or r.get("server_name") or "")) or None,
            dns_query=_unset(str(r.get("query") or "")) or None,
            signature_id=str(r.get("fuid") or "") or None,
            signature=str(signature)[:200] if signature else None,
            category=_PATH_TO_CATEGORY.get(path, "network"),
            message=str(r.get("msg") or r.get("sub") or "")[:2000] or None,
            raw=bounded_raw(raw),
            extra={**extra, "event_type": self._event_type(path, r)},
        ))

    @staticmethod
    def _event_type(path: str, r: Dict[str, Any]) -> str:
        if path == "notice":
            return "ids_notice"
        if path == "conn":
            state = str(r.get("conn_state") or "")
            return "network_connect" if state not in ("S0", "REJ", "RSTO") else "network_denied"
        if path == "dns":
            return "dns_query"
        if path == "http":
            return "http_request"
        if path == "ssl":
            return "tls_handshake"
        if path == "files":
            return "file_transfer"
        return f"zeek_{path}"
