"""Parser access log di proxy e web server: Squid e formato combined.

Un SIEM senza i log di proxy/web perde il canale più usato per esfiltrazione e
C2 (HTTP/HTTPS). Il formato combined (nginx/apache) e il log nativo Squid sono
i due che si incontrano nel 90% dei casi reali.

Supportati:
- Squid `access.log` nativo (`%ts.%03tu %>a %Ss/%03>Hs %<st %rm %ru %Sh/%<A %mt`),
- combined (nginx/apache): `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.ingest.base import (
    ParserError, UnifiedEvent, as_int, bounded_raw, finalize, make_event_id,
    parse_timestamp,
)

# Squid: ts.ms  ms  client  result/status  bytes  method  url  ident  hierarchy/peer  content-type
_SQUID = re.compile(
    r"^(?P<ts>\d{9,}(?:\.\d+)?)\s+(?P<elapsed>\d+)\s+(?P<client>\S+)\s+"
    r"(?P<result>[A-Z_]+)/(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+(?P<method>[A-Z]+)\s+"
    r"(?P<url>\S+)\s+(?P<ident>\S+)\s+(?P<hier>\S+)(?:\s+(?P<ctype>\S+))?"
)
# nginx/apache combined (+ variante con tempo di risposta in testa, usata da nginx)
_COMBINED = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s*)?(?:"(?P<ua>[^"]*)")?'
)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<version>HTTP/[\d.]+)$")

# Esiti Squid che indicano un blocco/rifiuto → severità e tipo di evento diversi.
_SQUID_DENIED = ("TCP_DENIED", "TCP_DENIED_REPLY", "ERR_", "UDP_DENIED")


class WebProxyParser:
    source_type = "web"

    def __init__(self, name: str = "web"):
        self.name = name

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        line = self._first_line(payload)
        if not line:
            return False
        is_squid = bool(_SQUID.match(line))
        m = _COMBINED.match(line)
        is_combined = bool(m and m.group("request"))
        # Istanze specifiche (squid / nginx) accettano solo il proprio formato;
        # l'istanza "web" generica accetta entrambi.
        if self.name == "squid":
            return is_squid
        if self.name in ("nginx", "apache", "httpd", "access_log"):
            return is_combined
        return is_squid or is_combined

    @staticmethod
    def _first_line(payload: Any) -> str:
        if isinstance(payload, dict):
            return ""
        text = payload if isinstance(payload, str) else ""
        for line in (text or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        return ""

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        if not isinstance(payload, str):
            raise ParserError("web access log must be text")
        source = meta.get("source") or self.name
        fallback_ts = parse_timestamp(meta.get("received_at"))
        events: List[UnifiedEvent] = []
        for line in payload.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            event = self._squid(line, source, fallback_ts) or self._combined(line, source, fallback_ts)
            if event is not None:
                events.append(event)
        if not events:
            raise ParserError("no parseable access log line")
        return events

    def _squid(self, line: str, source: str, fallback_ts) -> Optional[UnifiedEvent]:
        m = _SQUID.match(line)
        if not m:
            return None
        g = m.groupdict()
        status = as_int(g["status"])
        denied = any(g["result"].startswith(d) or d in g["result"] for d in _SQUID_DENIED)
        severity = "MEDIUM" if denied else ("LOW" if status and status >= 400 else "INFO")
        url = g["url"] if g["url"] != "-" else None
        return finalize(UnifiedEvent(
            time=parse_timestamp(g["ts"], default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            ocsf_class_uid=4002,
            severity=severity,
            ip=g["client"],
            src_ip=g["client"],
            user=None if g["ident"] == "-" else g["ident"],
            url=url,
            http_method=g["method"],
            http_status=status,
            domain=self._host_of(url),
            extra={"proxy_result": g["result"], "elapsed_ms": as_int(g["elapsed"]),
                   "bytes": None if g["bytes"] == "-" else as_int(g["bytes"]),
                   "hierarchy": g["hier"], "format": "squid",
                   "event_type": "proxy_denied" if denied else "http_request"},
            message=f"{g['method']} {url or '-'} -> {g['status']} ({g['result']})",
            raw=bounded_raw(line),
        ))

    def _combined(self, line: str, source: str, fallback_ts) -> Optional[UnifiedEvent]:
        m = _COMBINED.match(line)
        if not m or not m.group("request"):
            return None
        g = m.groupdict()
        req = _REQUEST.match(g["request"])
        method = req.group("method") if req else None
        target = req.group("target") if req else g["request"]
        status = as_int(g["status"])
        severity = "LOW" if status and status >= 400 else "INFO"
        host = self._host_of(target)
        return finalize(UnifiedEvent(
            time=parse_timestamp(g["ts"], default=fallback_ts),
            source=source,
            source_type=self.source_type,
            event_id=make_event_id(source, line),
            ocsf_class_uid=4002,
            severity=severity,
            ip=g["client"],
            src_ip=g["client"],
            user=None if g["user"] in ("-", None) else g["user"],
            url=target,
            http_method=method,
            http_status=status,
            user_agent=g.get("ua") or None,
            domain=host,
            extra={"bytes": None if g["bytes"] in ("-", None) else as_int(g["bytes"]),
                   "referer": g.get("referer"), "format": "combined",
                   "event_type": "http_request"},
            message=f"{method or '-'} {target} -> {g['status']}",
            raw=bounded_raw(line),
        ))

    @staticmethod
    def _host_of(url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        m = re.match(r"https?://([^/:]+)", url)
        if m:
            return m.group(1).lower()
        if url.startswith("/"):
            return None
        return url.split("/")[0].split(":")[0].lower() or None
