"""Parser Windows Event Log (JSON da wevtutil/Get-WinEvent, oppure XML).

Perché un parser dedicato: Windows Event Log è la sorgente più ricca che un
SIEM possa avere su un endpoint, e Sigma è nato per essa. Un parser generico
JSON perderebbe il significato di EventID e dei campi `EventData`, che sono
esattamente ciò su cui girano migliaia di regole Sigma (`TargetUserName`,
`CommandLine`, `IpAddress`, `ServiceName`…).

Gestisce tre forme reali:
1. JSON normalizzato dal collector (`{"Id":…, "EventData": {…}}`),
2. JSON di `Get-WinEvent | ConvertTo-Json` (campi in `Properties[].Value`),
3. XML di `wevtutil qe … /f:XML` (estrazione con regex bounded: nessuna
   entità esterna, nessun XXE).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_severity, parse_timestamp,
)

# EventID → (event_type, severità base, categoria, campo→nomi EventData)
WINDOWS_EVENTS: Dict[int, Dict[str, Any]] = {
    4624: {"event_type": "auth_success", "severity": "INFO", "category": "authentication",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"],
           "src_ip": ["IpAddress", "SourceNetworkAddress"], "logon_type": ["LogonType"],
           "process_name": ["ProcessName"], "hostname": ["WorkstationName"]},
    4625: {"event_type": "auth_failure", "severity": "HIGH", "category": "authentication",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"],
           "src_ip": ["IpAddress", "SourceNetworkAddress"], "logon_type": ["LogonType"],
           "process_name": ["ProcessName"], "hostname": ["WorkstationName"]},
    4634: {"event_type": "logoff", "severity": "INFO", "category": "authentication",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4647: {"event_type": "logoff", "severity": "INFO", "category": "authentication",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4648: {"event_type": "explicit_credentials", "severity": "MEDIUM", "category": "authentication",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"],
           "src_ip": ["IpAddress"], "process_name": ["ProcessName"]},
    4672: {"event_type": "special_privileges", "severity": "MEDIUM", "category": "authentication",
           "user": ["SubjectUserName"], "user_domain": ["SubjectDomainName"]},
    4688: {"event_type": "process_creation", "severity": "INFO", "category": "process",
           "process_name": ["NewProcessName"], "process_path": ["NewProcessName"],
           "command_line": ["CommandLine"], "parent_process_name": ["ParentProcessName"],
           "pid": ["NewProcessId"], "parent_pid": ["ProcessId"],
           "user": ["SubjectUserName"], "user_domain": ["SubjectDomainName"]},
    4697: {"event_type": "service_installed", "severity": "HIGH", "category": "persistence",
           "process_name": ["ImagePath", "ServiceFileName"],
           "file_path": ["ImagePath", "ServiceFileName"],
           "extra": ["ServiceName", "ServiceType"], "user": ["SubjectUserName"]},
    4698: {"event_type": "scheduled_task_created", "severity": "HIGH", "category": "persistence",
           "user": ["SubjectUserName"], "extra": ["TaskName"]},
    4699: {"event_type": "scheduled_task_deleted", "severity": "MEDIUM", "category": "persistence",
           "user": ["SubjectUserName"], "extra": ["TaskName"]},
    4700: {"event_type": "scheduled_task_enabled", "severity": "MEDIUM", "category": "persistence",
           "user": ["SubjectUserName"], "extra": ["TaskName"]},
    4702: {"event_type": "scheduled_task_updated", "severity": "MEDIUM", "category": "persistence",
           "user": ["SubjectUserName"], "extra": ["TaskName"]},
    4720: {"event_type": "user_account_created", "severity": "MEDIUM", "category": "account",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4722: {"event_type": "user_account_enabled", "severity": "MEDIUM", "category": "account",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4724: {"event_type": "password_reset", "severity": "MEDIUM", "category": "account",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4726: {"event_type": "user_account_deleted", "severity": "MEDIUM", "category": "account",
           "user": ["TargetUserName"], "user_domain": ["TargetDomainName"]},
    4728: {"event_type": "group_member_added", "severity": "HIGH", "category": "account",
           "user": ["MemberName"], "extra": ["TargetUserName", "GroupName"]},
    4732: {"event_type": "group_member_added", "severity": "HIGH", "category": "account",
           "user": ["MemberName"], "extra": ["TargetUserName", "GroupName"]},
    4756: {"event_type": "group_member_added", "severity": "HIGH", "category": "account",
           "user": ["MemberName"], "extra": ["TargetUserName", "GroupName"]},
    1102: {"event_type": "log_cleared", "severity": "CRITICAL", "category": "defense_evasion",
           "user": ["SubjectUserName"]},
    104: {"event_type": "log_cleared", "severity": "CRITICAL", "category": "defense_evasion"},
    7045: {"event_type": "service_installed", "severity": "HIGH", "category": "persistence",
           "process_name": ["ImagePath"], "file_path": ["ImagePath"],
           "extra": ["ServiceName", "ServiceType", "StartType"]},
    7040: {"event_type": "service_start_type_changed", "severity": "MEDIUM", "category": "persistence",
           "extra": ["ServiceName", "StartType"]},
    4103: {"event_type": "powershell_module", "severity": "INFO", "category": "script",
           "command_line": ["CommandLine", "Payload"], "user": ["UserId"]},
    4104: {"event_type": "powershell_script_block", "severity": "MEDIUM", "category": "script",
           "command_line": ["ScriptBlockText"], "user": ["UserId"]},
    1: {"event_type": "process_creation", "severity": "INFO", "category": "process",
        "process_name": ["Image"], "process_path": ["Image"], "command_line": ["CommandLine"],
        "parent_process_name": ["ParentImage"], "user": ["User"], "file_hash": ["Hashes"]},
    3: {"event_type": "network_connect", "severity": "INFO", "category": "network",
        "process_name": ["Image"], "src_ip": ["SourceIp"], "dst_ip": ["DestinationIp"],
        "dst_port": ["DestinationPort"], "protocol": ["Protocol"]},
    11: {"event_type": "file_created", "severity": "INFO", "category": "file",
         "file_path": ["TargetFilename"], "process_name": ["Image"]},
}

# Mappa posizionale per il JSON di `Get-WinEvent | ConvertTo-Json` quando
# EventData non c'è (i campi sono in `Properties` come lista ordinata).
# Ci limitiamo agli EventID più frequenti: una mappa sbagliata sarebbe peggio
# di nessuna mappa, quindi gli altri restano senza arricchimento strutturato.
_POSITIONAL: Dict[int, List[Tuple[str, str]]] = {
    4624: [("user", "user"), ("user_domain", "user_domain"), ("logon_type", "extra.logon_type"),
           ("src_ip", "src_ip")],
    4625: [("user", "user"), ("user_domain", "user_domain"), ("logon_type", "extra.logon_type"),
           ("src_ip", "src_ip")],
    4688: [("user", "user"), ("process_name", "process_name"), ("pid", "pid"),
           ("process_path", "process_path")],
}

_XML_DATA = re.compile(r'<Data\s+Name="([^"]+)"\s*>(.*?)</Data>', re.DOTALL)
_XML_DATA_EMPTY = re.compile(r'<Data\s+Name="([^"]+)"\s*/>')
_XML_SIMPLE = re.compile(r"<(?P<tag>EventID|Computer|Provider|Channel|Level|Task|"
                         r"SecurityUserID|Execution)[^>]*?(?P<attrs>[^>]*)>(?P<text>.*?)</(?P=tag)>", re.DOTALL)
_XML_ATTR = re.compile(r'([A-Za-z_]+)="([^"]*)"')
_TAG = re.compile(r"<[^>]+>")


def _strip_tags(text: str) -> str:
    return _TAG.sub("", text or "").strip()


def parse_windows_xml(raw: str) -> Optional[Dict[str, Any]]:
    """Estrae EventID/System/EventData da un XML Event senza parser XML esterno."""
    if "<Event" not in raw and "<event" not in raw:
        return None
    data: Dict[str, Any] = {}
    for name, value in _XML_DATA.findall(raw):
        data[str(name)] = _strip_tags(value)
    for name in _XML_DATA_EMPTY.findall(raw):
        data.setdefault(str(name), "")
    system: Dict[str, Any] = {}
    for m in _XML_SIMPLE.finditer(raw):
        tag = m.group("tag")
        if tag == "EventID":
            system["Id"] = as_int(_strip_tags(m.group("text")))
        elif tag == "Computer":
            system["Computer"] = _strip_tags(m.group("text"))
        elif tag == "Provider":
            attrs = dict(_XML_ATTR.findall(m.group("attrs") or ""))
            system["Provider"] = attrs.get("Name")
        elif tag == "Channel":
            system["Channel"] = _strip_tags(m.group("text"))
        elif tag == "Level":
            system["Level"] = as_int(_strip_tags(m.group("text")))
    ts = re.search(r'SystemTime="([^"]+)"', raw)
    if ts:
        system["TimeCreated"] = ts.group(1)
    if not system.get("Id"):
        return None
    return {"Id": system.get("Id"), "Computer": system.get("Computer"),
            "Provider": system.get("Provider"), "Channel": system.get("Channel"),
            "Level": system.get("Level"), "TimeCreated": system.get("TimeCreated"),
            "EventData": data, "Message": None}


class WindowsEventParser:
    name = "windows_event"
    source_type = "windows_event"

    # Un dict è un evento Windows solo se ha i marker di sistema. Senza questo
    # controllo il parser rivendicherebbe QUALUNQUE JSON (Suricata compreso) e
    # l'auto-detection diventerebbe inutile.
    _MARKERS = frozenset({
        "Id", "EventID", "EventData", "event_data", "Provider", "ProviderName",
        "Channel", "LogName", "Computer", "MachineName", "EventRecordID",
        "System", "TimeCreated", "LevelDisplayName",
    })

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        if isinstance(payload, dict):
            return bool(self._MARKERS & set(payload.keys()))
        if not isinstance(payload, str):
            return False
        # File NDJSON / più eventi: basta che le prime righe siano eventi
        # Windows; altrimenti il parser JSON generico se li prenderebbe tutti.
        lines = [line for line in payload.splitlines() if line.strip()][:3]
        for line in lines:
            if self._extract(line) is not None:
                return True
        return self._extract(payload) is not None

    @classmethod
    def _extract(cls, payload: Any) -> Optional[Dict[str, Any]]:
        """Normalizza le tre forme a un dizionario {Id, EventData, …} o None."""
        if isinstance(payload, dict):
            return payload if (cls._MARKERS & set(payload.keys())) else None
        if not isinstance(payload, str):
            return None
        text = payload.strip()
        if not text:
            return None
        if "<Event" in text:
            return parse_windows_xml(text)
        if text.startswith("{"):
            import json
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(obj, dict) and (cls._MARKERS & set(obj.keys())):
                return obj
            return None
        return None

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        source = meta.get("source") or "windows_event"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        if isinstance(payload, list):
            records: List[Any] = payload
        elif isinstance(payload, dict):
            records = payload["Events"] if isinstance(payload.get("Events"), list) else [payload]
        elif isinstance(payload, str):
            text = payload.strip()
            # Un singolo documento XML può essere indentato su più righe.
            if text.count("<Event") == 1:
                records = [text]
            else:
                records = [line for line in text.splitlines()
                           if line.strip() and not line.lstrip().startswith("#")]
        else:
            records = [payload]
        events: List[UnifiedEvent] = []
        for record in records:
            norm = self._extract(record)
            # `can_parse`/`_MARKERS` rivendicano anche la chiave `EventID` e
            # `_parse_record` la gestisce: scartarla qui faceva rifiutare con
            # "no Windows Event record found" un record che il parser aveva
            # dichiarato di saper leggere.
            if not norm or not (norm.get("Id") or norm.get("EventID")):
                continue
            events.append(self._parse_record(norm, source, fallback_ts))
        if not events:
            raise ParserError("no Windows Event record found")
        return events

    def _parse_record(self, rec: Dict[str, Any], source: str, fallback_ts) -> UnifiedEvent:
        event_id = as_int(rec.get("Id") if "Id" in rec else rec.get("EventID"))
        spec = WINDOWS_EVENTS.get(event_id or -1, {})

        data = self._event_data(rec)
        # Arricchimento posizionale sui Properties quando manca EventData.
        if not data and isinstance(rec.get("Properties"), list):
            names = [p.get("Value") for p in rec["Properties"] if isinstance(p, dict)]
            if names:
                data = {f"p{i}": v for i, v in enumerate(names)}

        def by_name(candidates: List[str]) -> Optional[Any]:
            if not data or not candidates:
                return None
            lower = {k.lower(): v for k, v in data.items()}
            for name in candidates:
                if name.lower() in lower:
                    value = lower[name.lower()]
                    if value not in (None, "", "-"):
                        return value
            return None

        host = (rec.get("Computer") or rec.get("MachineName")
                or by_name(["WorkstationName", "Computer"]))
        provider = rec.get("Provider") or rec.get("ProviderName")
        channel = rec.get("Channel") or rec.get("LogName")
        # Livello: prima LevelDisplayName (testo), poi Level numerico (1-5).
        level = rec.get("LevelDisplayName") or rec.get("Level")
        severity = normalize_severity(spec.get("severity", "INFO"))
        if level not in (None, ""):
            sev = normalize_severity(level, kind="windows") if str(level).strip().isdigit() \
                else normalize_severity(level)
            # Non abbassare la severità semantica dell'EventID (es. un 4625
            # "Information" resta HIGH: è un logon fallito, non un file aperto).
            order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if order[sev] > order[severity]:
                severity = sev

        message = rec.get("Message")
        if isinstance(message, dict):  # {"#text": "..."} da XML
            message = message.get("#text")
        message = _strip_tags(str(message)) if message else None

        extra: Dict[str, Any] = {"event_id": event_id, "raw_event_id": event_id}
        if provider:
            extra["provider"] = provider
        if channel:
            extra["channel"] = channel
        for key in ("Task", "Keywords", "Opcode"):
            if rec.get(key) not in (None, ""):
                extra[key.lower()] = rec[key]
        # Tutti i campi EventData restano cercabili: nessun dato perso.
        for k, v in (data or {}).items():
            if isinstance(v, (str, int, float)) and len(str(v)) < 500:
                extra[f"win.{k}"] = v
        for name in spec.get("extra", []):
            value = by_name([name])
            if value is not None:
                extra[f"win.{name}"] = value

        logon_type = by_name(spec.get("logon_type", []))
        if logon_type is not None:
            extra["logon_type"] = logon_type

        pid = as_int(by_name(spec.get("pid", [])))
        parent_pid = as_int(by_name(spec.get("parent_pid", [])))

        return finalize(UnifiedEvent(
            time=parse_timestamp(rec.get("TimeCreated") or rec.get("TimeGenerated")
                                 or rec.get("SystemTime"), default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, rec),
            ocsf_class_uid=3002 if str(spec.get("event_type", "")).startswith("auth") else 0,
            severity=severity,
            hostname=str(host) if host else None,
            user=by_name(spec.get("user", [])) or None,
            user_domain=by_name(spec.get("user_domain", [])) or None,
            process_name=by_name(spec.get("process_name", [])) or None,
            pid=pid,
            parent_process_name=by_name(spec.get("parent_process_name", [])) or None,
            parent_pid=parent_pid,
            process_path=by_name(spec.get("process_path", [])) or None,
            command_line=by_name(spec.get("command_line", [])) or None,
            file_path=by_name(spec.get("file_path", [])) or None,
            file_hash=by_name(spec.get("file_hash", [])) or None,
            src_ip=by_name(spec.get("src_ip", [])) or None,
            dst_ip=by_name(spec.get("dst_ip", [])) or None,
            dst_port=as_int(by_name(spec.get("dst_port", []))),
            protocol=by_name(spec.get("protocol", [])) or None,
            signature_id=str(event_id) if event_id else None,
            signature=str(provider) if provider else None,
            category=spec.get("category"),
            message=message[:2000] if message else None,
            message_id=str(event_id) if event_id else None,
            raw=bounded_raw(rec),
            extra={**extra, "event_type": spec.get("event_type", "windows_event")},
        ))

    @staticmethod
    def _event_data(rec: Dict[str, Any]) -> Dict[str, Any]:
        for key in ("EventData", "event_data", "Data"):
            value = rec.get(key)
            if isinstance(value, dict):
                return value
            if isinstance(value, list):
                out: Dict[str, Any] = {}
                for item in value:
                    if isinstance(item, dict):
                        name = item.get("Name") or item.get("name")
                        val = item.get("Value", item.get("value", item.get("#text")))
                        if name:
                            out[str(name)] = val
                if out:
                    return out
        return {}
