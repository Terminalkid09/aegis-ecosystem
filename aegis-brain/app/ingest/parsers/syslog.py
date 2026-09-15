"""Parser syslog RFC5424 e RFC3164 (+ variante Cisco/ASA).

È il formato di fatto di firewall, switch, NAS, appliance e device IoT: senza
questo parser un SIEM non è un SIEM. Il PRI (`<134>`) contiene facility e
severity, ed è l'unica fonte affidabile di severità per un dispositivo che non
manda JSON.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    normalize_severity, parse_timestamp,
)

# RFC5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s"
    r"(?P<ts>\S+)\s(?P<host>\S+)\s(?P<app>\S+)\s(?P<procid>\S+)\s(?P<msgid>\S+)\s"
    r"(?P<sd>-|\[.*?\])(?:\s(?P<msg>.*))?$",
    re.DOTALL,
)
# RFC3164: <PRI>MMM dd hh:mm:ss HOST TAG[pid]: MSG
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<tag>[^:\[]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    re.DOTALL,
)
# Variante senza timestamp (relay che aggiunge l'ora): <PRI>TAG: MSG
_NO_TS = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<tag>[A-Za-z0-9._/-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    re.DOTALL,
)

_FACILITIES = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4",
    21: "local5", 22: "local6", 23: "local7",
}

# Tag noti che indicano auth/login → il messaggio va arricchito per la
# correlazione (brute force) e ha severità minima MEDIUM.
_AUTH_TAGS = ("ssh", "sshd", "sudo", "su", "login", "systemd-logind", "gdm",
              "winbind", "krb5", "pam")
_FAILED_AUTH = re.compile(r"(?i)(failed password|authentication failure|invalid user|"
                          r"failed login|login failed|auth(?:entication)? fail|"
                          r"incorrect password|access denied)")
_ACCEPTED_AUTH = re.compile(r"(?i)(accepted (password|publickey)|session opened for user|"
                          r"login successful|successful login|new session)")
# IPv4 nel messaggio: per la correlazione brute-force serve il mittente, e in
# syslog (a differenza di JSON) non è un campo ma testo libero.
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class SyslogParser:
    name = "syslog"
    source_type = "syslog"

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        line = self._first_line(payload)
        return bool(re.match(r"^<(?:\d{1,3})>", line))

    @staticmethod
    def _first_line(payload: Any) -> str:
        text = payload if isinstance(payload, str) else str(payload.get("message", "") if isinstance(payload, dict) else payload)
        return (text or "").splitlines()[0] if text else ""

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        text = payload if isinstance(payload, str) else str(payload.get("message", "") if isinstance(payload, dict) else payload)
        if not text:
            raise ParserError("empty syslog payload")
        source = meta.get("source") or "syslog"
        fallback_ts = parse_timestamp(meta.get("received_at"))
        events: List[UnifiedEvent] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            event = self._parse_line(line, source, fallback_ts)
            if event is not None:
                events.append(event)
        if not events:
            raise ParserError("no parseable syslog line")
        return events

    def _parse_line(self, line: str, source: str, fallback_ts: datetime) -> Optional[UnifiedEvent]:
        pri = ts_text = host = app = procid = msgid = sd = msg = None
        structured = False

        m = _RFC5424.match(line)
        if m and m.group("ts") != "-":
            g = m.groupdict()
            pri, ts_text, host = g["pri"], g["ts"], g["host"]
            app, procid, msgid, sd = g["app"], g["procid"], g["msgid"], g["sd"]
            msg = g.get("msg")
            structured = True
        else:
            m = _RFC3164.match(line) or _NO_TS.match(line)
            if not m:
                return None
            g = m.groupdict()
            pri, host = g["pri"], g.get("host")
            ts_text = g.get("ts")
            app, procid = g.get("tag"), g.get("pid")
            msg = g.get("msg")

        pri_i = as_int(pri) or 13
        facility = _FACILITIES.get(pri_i // 8)
        severity = normalize_severity(pri_i % 8, kind="syslog")
        ts = parse_timestamp(ts_text, default=fallback_ts) if ts_text else fallback_ts

        message = (msg or sd or "").strip()
        tag = (app or "").strip()
        user = self._extract_user(message)
        src_ip = self._extract_ip(message)
        event_type = "syslog"

        # Auth: alza la severità e classifica l'esito, così la correlazione
        # brute-force lavora su campi strutturati invece che su regex al volo.
        category = None
        if tag.lower() in _AUTH_TAGS or any(t in tag.lower() for t in _AUTH_TAGS):
            event_type = "auth"
            category = "authentication"
            if _FAILED_AUTH.search(message):
                severity = "HIGH" if severity in ("INFO", "LOW", "MEDIUM") else severity
                event_type = "auth_failure"
            elif _ACCEPTED_AUTH.search(message):
                event_type = "auth_success"
        if facility == "authpriv":
            category = category or "authentication"

        extra: Dict[str, Any] = {}
        if tag:
            extra["syslog_tag"] = tag
        if facility:
            extra["facility"] = facility
        if procid and procid != "-":
            extra["procid"] = procid
        if msgid and msgid != "-":
            extra["msgid"] = msgid
        if structured:
            extra["rfc"] = "5424"
        elif _RFC3164.match(line):
            extra["rfc"] = "3164"

        return finalize(UnifiedEvent(
            time=ts,
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            # OCSF 3002 = Authentication; per gli altri syslog la classe non è
            # determinabile in modo affidabile, quindi 0 ("non determinato")
            # invece di un valore inventato.
            ocsf_class_uid=3002 if event_type.startswith("auth") else 0,
            severity=severity,
            hostname=host if host not in (None, "-") else None,
            ip=src_ip,
            user=user,
            process_name=tag or None,
            pid=as_int(procid),
            src_ip=src_ip,
            message=message[:2000] or None,
            raw=bounded_raw(line),
            extra={**extra, "event_type": event_type, **({"category": category} if category else {})},
        ))

    @staticmethod
    def _extract_user(message: str) -> Optional[str]:
        for pattern in (r"(?i)for (?:invalid )?user (\S+)", r"(?i)user[= ](\S+)",
                        r"(?i)by \((\S+)\)", r"(?i)for (\S+) from"):
            m = re.search(pattern, message)
            if m:
                return m.group(1).strip("',;:")
        return None

    @staticmethod
    def _extract_ip(message: str) -> Optional[str]:
        m = _IPV4.search(message)
        if not m:
            return None
        ip = m.group(1)
        # Scarta valori impossibili (es. versione "1.2.3.4" mai validi restano
        # validi: qui filtriamo solo ottetti fuori range).
        if any(int(part) > 255 for part in ip.split(".")):
            return None
        return ip
