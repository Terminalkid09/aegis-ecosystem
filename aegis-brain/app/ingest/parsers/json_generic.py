"""Parser JSON/NDJSON generico con dizionario di alias.

È il parser di fallback intelligente: quasi tutti gli shipper (Filebeat, Fluent
Bit, Vector, script custom) mandano JSON. Invece di chiedere al cliente di
rinominare i campi, mappiamo qui gli alias che i prodotti usano davvero
(`@timestamp`, `Image`, `CommandLine`, `IpAddress`, `dst_ip`, …) verso lo
schema unificato. I campi non riconosciuti restano in `extra`, quindi nulla va
perso e la ricerca libera li vede comunque.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_protocol, normalize_severity, parse_timestamp,
)

# alias → campo unificato. Confronto case-insensitive sul nome foglia
# (l'ultimo segmento di un path puntato, es. "winlog.event_data.TargetUserName").
_ALIASES: Dict[str, str] = {
    # tempo
    "timestamp": "time", "time": "time", "@timestamp": "time",
    "event_time": "time", "eventtime": "time", "datetime": "time",
    "utctime": "time", "ts": "time",
    # host / device
    "host": "hostname", "hostname": "hostname", "computername": "hostname",
    "computer": "hostname", "device": "hostname", "host_name": "hostname",
    "agent_hostname": "hostname", "syslog_hostname": "hostname",
    "ip": "ip", "ipaddress": "ip", "ip_address": "ip", "host_ip": "ip",
    "local_ip": "ip",
    # utente
    "user": "user", "username": "user", "user_name": "user",
    "accountname": "user", "targetusername": "user", "subjectusername": "user",
    "userid": "user", "account": "user", "src_user": "user",
    "accountdomain": "user_domain", "targetdomainname": "user_domain",
    "ad_domain": "user_domain",
    # processo
    "process": "process_name", "process_name": "process_name",
    "processname": "process_name", "image": "process_name",
    "newprocessname": "process_name", "exe": "process_name",
    "executable": "process_name", "application": "process_name",
    "parentprocessname": "parent_process_name", "parent_process": "parent_process_name",
    "parentimage": "parent_process_name",
    "commandline": "command_line", "command_line": "command_line",
    "cmd": "command_line", "cmdline": "command_line", "process_command_line": "command_line",
    "processid": "pid", "pid": "pid", "newprocessid": "pid", "process_id": "pid",
    "parentprocessid": "parent_pid", "ppid": "parent_pid", "parent_pid": "parent_pid",
    "processpath": "process_path", "process_path": "process_path",
    # file
    "filepath": "file_path", "file_path": "file_path", "targetfilename": "file_path",
    "path": "file_path", "fullpath": "file_path",
    "filename": "file_name", "file_name": "file_name", "targetname": "file_name",
    "hash_sha256": "file_hash", "sha256": "file_hash", "filehash": "file_hash",
    "hashes": "file_hash", "md5": "file_hash",
    # rete
    "src_ip": "src_ip", "source_ip": "src_ip", "sourceip": "src_ip",
    "src": "src_ip", "client_ip": "src_ip", "ip_src": "src_ip", "sourceaddress": "src_ip",
    "dst_ip": "dst_ip", "dest_ip": "dst_ip", "destination_ip": "dst_ip",
    "destinationip": "dst_ip", "dst": "dst_ip", "server_ip": "dst_ip",
    "ip_dst": "dst_ip", "destinationaddress": "dst_ip",
    "src_port": "src_port", "source_port": "src_port", "sourceport": "src_port",
    "sport": "src_port",
    "dst_port": "dst_port", "dest_port": "dst_port", "destination_port": "dst_port",
    "destinationport": "dst_port", "dport": "dst_port", "port": "dst_port",
    "protocol": "protocol", "proto": "protocol", "transport": "protocol",
    # applicativo
    "url": "url", "uri": "url", "request_url": "url", "request": "url",
    "http_method": "http_method", "method": "http_method", "verb": "http_method",
    "status_code": "http_status", "status": "http_status", "http_status": "http_status",
    "useragent": "user_agent", "user_agent": "user_agent", "http_user_agent": "user_agent",
    "domain_name": "domain", "fqdn": "domain", "hostname_queried": "domain",
    "query": "dns_query", "dns_query": "dns_query", "question": "dns_query",
    # detection della sorgente
    "signature": "signature", "signature_id": "signature_id", "signatureid": "signature_id",
    "alert_signature": "signature", "rule": "signature",
    "category": "category", "eventcategory": "category",
    # messaggio / severità
    "message": "message", "msg": "message", "description": "message",
    "severity": "severity", "level": "severity", "severity_label": "severity",
    "loglevel": "severity",
    # messaggio Windows
    "event_code": "message_id", "provider": "extra_provider",
}


def _iter_leaves(obj: Any, prefix: str = "") -> Iterable[tuple]:
    """Deriva (path, leaf_name, value) ricorsivamente, max 3 livelli.

    Il limite di profondità evita di esplodere su payload profondi/anomali e
    tiene il costo di parsing lineare.
    """
    if prefix.count(".") >= 3:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                yield from _iter_leaves(value, path)
            else:
                yield path, str(key).lower(), value
    elif isinstance(obj, list):
        for item in obj[:200]:
            if isinstance(item, (dict, list)):
                yield from _iter_leaves(item, prefix)
            else:
                yield prefix, prefix.split(".")[-1].lower(), item


class JsonGenericParser:
    name = "json"
    source_type = "json"

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        if isinstance(payload, (dict, list)):
            return True
        if not isinstance(payload, str):
            return False
        text = payload.strip()
        if not text or text[0] not in "{[":
            return False
        try:
            json.loads(text.splitlines()[0] if text.splitlines() else text)
            return True
        except (json.JSONDecodeError, IndexError):
            return False

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        source = meta.get("source") or "json"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        records = self._as_records(payload)
        if not records:
            raise ParserError("no JSON record found")
        events: List[UnifiedEvent] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            events.append(self._parse_record(record, source, fallback_ts))
        if not events:
            raise ParserError("no JSON object parsed")
        return events

    @staticmethod
    def _as_records(payload: Any) -> List[Any]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            # Batch wrapper comune: {"events": [...]} / {"logs": [...]}
            for key in ("events", "logs", "records", "items"):
                if isinstance(payload.get(key), list):
                    return payload[key]
            return [payload]
        if not isinstance(payload, str):
            return []
        text = payload.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            # NDJSON: una riga = un oggetto
            out = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return out
        return parsed if isinstance(parsed, list) else [parsed]

    def _parse_record(self, record: Dict[str, Any], source: str,
                      fallback_ts) -> UnifiedEvent:
        mapped: Dict[str, Any] = {}
        extra: Dict[str, Any] = {}
        for path, leaf, value in _iter_leaves(record):
            field = _ALIASES.get(leaf)
            if field == "time":
                mapped.setdefault("time", value)
            elif field == "extra_provider":
                extra["provider"] = value
            elif field and field not in mapped:
                mapped[field] = value
            elif path not in ("time",) and len(extra) < 60:
                extra[path] = value

        severity_raw = mapped.pop("severity", None)
        # Livelli numerici Windows (1..5) vs etichette testuali.
        kind = "windows" if str(severity_raw).strip().isdigit() and 1 <= int(str(severity_raw)) <= 5 else "label"

        return finalize(UnifiedEvent(
            time=parse_timestamp(mapped.pop("time", None), default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, json.dumps(record, sort_keys=True, default=str)),
            severity=normalize_severity(severity_raw, kind=kind),
            hostname=mapped.get("hostname"),
            ip=mapped.get("ip"),
            user=mapped.get("user"),
            user_domain=mapped.get("user_domain"),
            process_name=mapped.get("process_name"),
            pid=as_int(mapped.get("pid")),
            parent_process_name=mapped.get("parent_process_name"),
            parent_pid=as_int(mapped.get("parent_pid")),
            process_path=mapped.get("process_path"),
            command_line=mapped.get("command_line"),
            file_path=mapped.get("file_path"),
            file_name=mapped.get("file_name"),
            file_hash=mapped.get("file_hash"),
            src_ip=mapped.get("src_ip"),
            src_port=as_int(mapped.get("src_port")),
            dst_ip=mapped.get("dst_ip"),
            dst_port=as_int(mapped.get("dst_port")),
            protocol=normalize_protocol(mapped.get("protocol")),
            url=mapped.get("url"),
            http_method=mapped.get("http_method"),
            http_status=as_int(mapped.get("http_status")),
            user_agent=mapped.get("user_agent"),
            domain=mapped.get("domain"),
            dns_query=mapped.get("dns_query"),
            signature_id=str(mapped["signature_id"]) if mapped.get("signature_id") is not None else None,
            signature=mapped.get("signature"),
            category=mapped.get("category"),
            message=str(mapped.get("message"))[:2000] if mapped.get("message") else None,
            message_id=str(mapped["message_id"]) if mapped.get("message_id") is not None else None,
            raw=bounded_raw(record),
            extra=extra,
        ))
