"""Mappatura dei nomi campo Sigma sull'evento unificato.

Le regole Sigma usano i nomi dei prodotti da cui provengono: `Image`,
`CommandLine`, `TargetUserName`, `EventID` per Windows; `src_ip`, `query`,
`note` per rete. Qui quei nomi vengono risolti sullo schema unificato
(`app.ingest.base.UnifiedEvent`).

Ordine di risoluzione (per un campo `X`):
1. alias esplicito (mappa sotto),
2. campo diretto del modello con lo stesso nome (case-insensitive),
3. `extra` per chiave esatta, `win.X`, o match case-insensitive sufisso.

Il fallback 3 è ciò che rende il motore utile senza riscrivere le regole: i
parser mettono già ogni campo sorgente in `extra` (es. `win.ServiceName`,
`conn_state`), quindi una regola Sigma trova il dato anche se lo schema
unificato non ha una colonna dedicata.
"""
from __future__ import annotations

from typing import Any, List, Optional

from app.ingest.base import UnifiedEvent

# Nome diretto, case-insensitive, dei campi del modello.
_DIRECT = {name.lower(): name for name in UnifiedEvent.model_fields}

# Sigma field → percorsi nell'evento. `extra.` seleziona l'omonimo dict.
_ALIASES = {
    # Windows / Event Log
    "eventid": ["message_id", "extra.event_id"],
    "eventcode": ["message_id", "extra.event_id"],
    "provider_name": ["signature", "extra.provider"],
    "channel": ["extra.channel"],
    "computer": ["hostname"],
    "image": ["process_path", "process_name"],
    "originalfilename": ["file_name"],
    "newname": ["file_name"],
    "commandline": ["command_line"],
    "parentcommandline": ["extra.win.ParentCommandLine"],
    "parentimage": ["parent_process_name"],
    "parentprocessname": ["parent_process_name"],
    "processname": ["process_name"],
    "newprocessname": ["process_path", "process_name"],
    "processid": ["pid"],
    "newprocessid": ["pid"],
    "parentprocessid": ["parent_pid"],
    "targetusername": ["user"],
    "subjectusername": ["user"],
    "user": ["user"],
    "username": ["user"],
    "targetdomainname": ["user_domain"],
    "subjectdomainname": ["user_domain"],
    "logontype": ["extra.logon_type", "extra.win.LogonType"],
    "ipaddress": ["src_ip", "ip"],
    "sourceip": ["src_ip", "ip"],
    "workstationname": ["hostname"],
    "targetfilename": ["file_path"],
    "filename": ["file_name", "file_path"],
    "imagepath": ["file_path", "process_path", "extra.win.ImagePath"],
    "servicename": ["extra.win.ServiceName"],
    "servicetype": ["extra.win.ServiceType"],
    "starttype": ["extra.win.StartType"],
    "taskname": ["extra.win.TaskName"],
    "hashes": ["file_hash"],
    "sha256": ["file_hash"],
    "scriptblocktext": ["command_line"],
    "payload": ["command_line"],
    "processcommandline": ["command_line"],
    # Linux / syslog
    "program": ["extra.syslog_tag", "process_name"],
    "syslog_tag": ["extra.syslog_tag"],
    # Rete
    "src_ip": ["src_ip", "ip"],
    "source_ip": ["src_ip"],
    "srcip": ["src_ip"],
    "id.orig_h": ["src_ip"],
    "dst_ip": ["dst_ip"],
    "dest_ip": ["dst_ip"],
    "destinationip": ["dst_ip"],
    "id.resp_h": ["dst_ip"],
    "src_port": ["src_port"],
    "srcport": ["src_port"],
    "id.orig_p": ["src_port"],
    "dst_port": ["dst_port"],
    "dest_port": ["dst_port"],
    "destinationport": ["dst_port"],
    "id.resp_p": ["dst_port"],
    "proto": ["protocol"],
    "protocol": ["protocol"],
    "app_proto": ["extra.app_proto"],
    "conn_state": ["extra.conn_state"],
    "service": ["extra.service"],
    "query": ["dns_query"],
    "queryname": ["dns_query"],
    "dns.query": ["dns_query"],
    "url": ["url"],
    "uri": ["url"],
    "http.url": ["url"],
    "method": ["http_method"],
    "http_method": ["http_method"],
    "status_code": ["http_status"],
    "useragent": ["user_agent"],
    "user_agent": ["user_agent"],
    "http.user_agent": ["user_agent"],
    "host": ["domain", "hostname"],
    "hostname": ["domain", "hostname"],
    "domain": ["domain"],
    "fqdn": ["domain"],
    "sni": ["extra.sni"],
    "ja3": ["extra.ja3"],
    # IDS
    "alert.signature": ["signature"],
    "alert.signature_id": ["signature_id"],
    "alert.category": ["category", "extra.alert_category"],
    "alert.action": ["extra.alert_action"],
    "alert.severity": ["extra.alert_severity"],
    "signature": ["signature"],
    "signature_id": ["signature_id"],
    "note": ["signature"],
    "rule": ["signature"],
    # Aegis / normalizzato
    "event_type": ["extra.event_type"],
    "eventtype": ["extra.event_type"],
    "severity": ["severity"],
    "source": ["source"],
    "source_type": ["source_type"],
    "file_path": ["file_path"],
    "process_path": ["process_path"],
    "command_line": ["command_line"],
    "process_name": ["process_name"],
    "parent_process_name": ["parent_process_name"],
    "hostname_net": ["hostname"],
    "dns_query": ["dns_query"],
    "category": ["category"],
}

# Campi che possono contenere PII/segreti da non loggare in chiaro: usati dal
# redactor quando un match viene persistito nell'audit/alert.
SENSITIVE_FIELDS = frozenset({"commandline", "scriptblocktext", "payload", "url", "query"})


def _dig(event: UnifiedEvent, path: str) -> Optional[Any]:
    if path.startswith("extra."):
        return event.extra.get(path[len("extra."):])
    return getattr(event, path, None)


def has_field(event: UnifiedEvent, name: str) -> bool:
    """True se il campo esiste (anche con valore vuoto) nell'evento o in extra."""
    key = name.strip().lower()
    for path in _ALIASES.get(key, []):
        if _dig(event, path) is not None:
            return True
    if key in _DIRECT:
        return getattr(event, _DIRECT[key], None) is not None
    if name in event.extra or f"win.{name}" in event.extra:
        return True
    return any(k.lower() == key or k.lower().endswith("." + key) for k in event.extra)


def get_values(event: UnifiedEvent, name: str) -> List[Any]:
    """Valori associati al campo Sigma. Lista vuota = campo assente.

    Ritorna una lista perché più percorsi possono contribuire (es. `Image`
    mappato sia su `process_path` sia su `process_name`): una regola che cerca
    il percorso completo deve trovare la corrispondenza se in uno dei due c'è.
    """
    key = name.strip().lower()
    out: List[Any] = []
    for path in _ALIASES.get(key, []):
        value = _dig(event, path)
        if value not in (None, "", [], {}):
            out.append(value)
    if out:
        return out
    direct = _DIRECT.get(key)
    if direct:
        value = getattr(event, direct, None)
        if value not in (None, "", [], {}):
            return [value]
    extra = event.extra
    for candidate in (name, f"win.{name}", name.lower(), f"win.{name.lower()}"):
        if candidate in extra and extra[candidate] not in (None, ""):
            return [extra[candidate]]
    for k, v in extra.items():
        low = k.lower()
        if (low == key or low.endswith("." + key)) and v not in (None, "", [], {}):
            out.append(v)
    return out
