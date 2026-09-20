"""Parser Suricata `eve.json` (NDJSON multi-tipo).

Suricata è l'IDS/IPS più diffuso negli ambienti open. `eve.json` è un flusso
di eventi eterogenei (`alert`, `flow`, `dns`, `http`, `tls`, `fileinfo`, `ssh`)
chiave per un SIEM: è qui che la rete produce detection pronte e metadati
(app_proto, JA3, hash dei file) che l'endpoint non vede.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_protocol, normalize_severity, parse_timestamp,
)

# Suricata alert.severity: 1 = più importante (high), 3 = meno.
_SURICATA_SEVERITY = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}

_EVENT_TYPES = {"alert", "flow", "dns", "http", "tls", "fileinfo", "ssh",
                "smb", "ftp", "smtp", "dhcp", "anomaly", "stats", "drop"}


class SuricataParser:
    name = "suricata"
    source_type = "suricata"

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        records = self._records(payload)
        for record in records[:3]:
            if isinstance(record, dict) and record.get("event_type") in _EVENT_TYPES \
                    and ("flow_id" in record or "src_ip" in record or "timestamp" in record):
                return True
        return False

    @staticmethod
    def _records(payload: Any) -> List[Any]:
        if isinstance(payload, (dict, list)):
            return payload if isinstance(payload, list) else [payload]
        if not isinstance(payload, str):
            return []
        out: List[Any] = []
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        source = meta.get("source") or "suricata"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        records = self._records(payload)
        events: List[UnifiedEvent] = []
        for record in records:
            if not isinstance(record, dict) or not record.get("event_type"):
                continue
            if record.get("event_type") == "stats":
                continue  # rumore operativo, non telemetria di sicurezza
            events.append(self._from_record(record, source, fallback_ts))
        if not events:
            raise ParserError("no Suricata eve record")
        return events

    def _from_record(self, r: Dict[str, Any], source: str, fallback_ts) -> UnifiedEvent:
        etype = str(r.get("event_type"))
        alert = r.get("alert") if isinstance(r.get("alert"), dict) else {}
        dns = r.get("dns") if isinstance(r.get("dns"), dict) else {}
        http = r.get("http") if isinstance(r.get("http"), dict) else {}
        tls = r.get("tls") if isinstance(r.get("tls"), dict) else {}
        fileinfo = r.get("fileinfo") if isinstance(r.get("fileinfo"), dict) else {}
        ssh = r.get("ssh") if isinstance(r.get("ssh"), dict) else {}

        severity = "INFO"
        if etype == "alert":
            sev = alert.get("severity")
            severity = _SURICATA_SEVERITY.get(sev if isinstance(sev, int) else as_int(sev), "MEDIUM")
            severity = normalize_severity(alert.get("severity_label") or severity)

        extra: Dict[str, Any] = {"suricata_event_type": etype}
        for key, value in (("flow_id", r.get("flow_id")), ("app_proto", r.get("app_proto")),
                           ("community_id", r.get("community_id")), ("pkt_src", r.get("pkt_src")),
                           ("tx_id", r.get("tx_id"))):
            if value not in (None, ""):
                extra[key] = value
        if alert:
            extra.update({
                "alert_action": alert.get("action"),
                "alert_category": alert.get("category"),
                "signature_rev": alert.get("rev"),
                "signature_gid": alert.get("gid"),
                "alert_severity": alert.get("severity"),
                "alert_metadata": alert.get("metadata") if isinstance(alert.get("metadata"), list) else None,
            })
        if etype == "fileinfo":
            for key in ("filename", "md5", "sha1", "sha256", "size", "state", "magic"):
                if fileinfo.get(key) not in (None, ""):
                    extra[f"file_{key}"] = fileinfo[key]
        if etype == "tls":
            ja3 = tls.get("ja3") if isinstance(tls.get("ja3"), dict) else {}
            for key, value in (("sni", tls.get("sni")), ("tls_version", tls.get("version")),
                               ("ja3", ja3.get("hash")), ("ja3s", tls.get("ja3s")),
                               ("subject", tls.get("subject"))):
                if value not in (None, ""):
                    extra[key] = value
        if etype == "ssh" and ssh:
            extra["ssh_client"] = (ssh.get("client") or {}).get("software_version")
            extra["ssh_server"] = (ssh.get("server") or {}).get("software_version")
        if etype in ("http", "dns", "tls") and r.get("proto"):
            extra["proto_raw"] = r.get("proto")

        dns_query = dns.get("rrname") or dns.get("query")
        file_hash = fileinfo.get("sha256") or fileinfo.get("md5") or fileinfo.get("sha1")
        # `flow.start` è il fallback ufficiale quando manca `timestamp`.
        flow = r.get("flow") if isinstance(r.get("flow"), dict) else {}
        ts_value = r.get("timestamp") or flow.get("start")

        return finalize(UnifiedEvent(
            time=parse_timestamp(ts_value, default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, r),
            ocsf_class_uid={"alert": 2004, "dns": 4003, "http": 4002, "tls": 4001,
                            "flow": 4001, "fileinfo": 1001}.get(etype, 0),
            severity=severity,
            hostname=r.get("host") or None,
            ip=r.get("src_ip") or None,
            src_ip=r.get("src_ip") or None,
            src_port=as_int(r.get("src_port")),
            dst_ip=r.get("dest_ip") or r.get("dst_ip") or None,
            dst_port=as_int(r.get("dest_port") or r.get("dst_port")),
            protocol=normalize_protocol(r.get("proto") or r.get("app_proto")),
            url=str(http.get("url"))[:2000] if http.get("url") else None,
            http_method=str(http.get("http_method"))[:16] if http.get("http_method") else None,
            http_status=as_int(http.get("status")),
            user_agent=str(http.get("http_user_agent"))[:1000] if http.get("http_user_agent") else None,
            domain=http.get("hostname") or tls.get("sni") or None,
            dns_query=dns_query,
            file_name=fileinfo.get("filename"),
            file_hash=file_hash,
            signature_id=str(alert.get("signature_id")) if alert.get("signature_id") is not None else None,
            signature=alert.get("signature"),
            category=alert.get("category") or etype,
            message=str(alert.get("signature") or dns_query or http.get("url") or etype)[:2000],
            raw=bounded_raw(r),
            extra={**extra, "event_type": etype},
        ))
