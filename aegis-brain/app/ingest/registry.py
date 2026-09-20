"""Registry dei parser: selezione esplicita o auto-detection.

Regola di fondo: **non si indovina**. Se nessun parser riconosce il payload,
l'evento viene contato come `unparsed` invece di essere trasformato in un
evento vuoto. Un SIEM che inventa eventi produce falsi negativi silenziosi, la
cosa più pericolosa che possa fare.

L'ordine di registrazione è l'ordine di auto-detection: i parser specifici
prima, il JSON generico per ultimo (è l'unico volutamente permissivo).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.ingest.base import Parser, ParserError, UnifiedEvent
from app.ingest.parsers.firewall import FirewallParser
from app.ingest.parsers.json_generic import JsonGenericParser
from app.ingest.parsers.suricata import SuricataParser
from app.ingest.parsers.syslog import SyslogParser
from app.ingest.parsers.web_proxy import WebProxyParser
from app.ingest.parsers.windows_event import WindowsEventParser
from app.ingest.parsers.zeek import ZeekParser

MAX_AUTO_LINES = 500   # bound sull'auto-detection riga-per-riga


@dataclass
class ParseResult:
    """Esito di una ingestione: eventi validi + diagnostica onesta."""

    events: List[UnifiedEvent] = field(default_factory=list)
    parser: Optional[str] = None
    unparsed: int = 0
    errors: List[str] = field(default_factory=list)
    detected_by: str = "source"   # "source" | "auto" | "auto-line"

    @property
    def ok(self) -> bool:
        return bool(self.events)


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: Dict[str, Parser] = {}
        self._order: List[str] = []
        self._generic: set = set()

    def register(self, parser: Parser, aliases: Sequence[str] = (),
                 generic: bool = False) -> None:
        self._parsers[parser.name] = parser
        for alias in aliases:
            self._parsers[alias] = parser
        if parser.name not in self._order:
            self._order.append(parser.name)
        if generic:
            self._generic.add(parser.name)

    def get(self, name: str) -> Optional[Parser]:
        return self._parsers.get((name or "").strip().lower())

    def names(self) -> List[str]:
        """Nomi canonici (senza alias) in ordine di auto-detection."""
        return list(self._order)

    def detect(self, payload: Any, meta: Dict[str, Any],
               skip_generic: bool = False) -> Optional[Parser]:
        for name in self._order:
            if skip_generic and name in self._generic:
                continue
            parser = self._parsers[name]
            try:
                if parser.can_parse(payload, meta):
                    return parser
            except Exception:
                continue
        return None

    def parse(self, source: str, payload: Any,
              meta: Optional[Dict[str, Any]] = None) -> ParseResult:
        """Ingerisce un payload con un parser esplicito o in auto-detection.

        I byte vengono decodificati qui e non nei parser: uno shipper reale
        (Filebeat, Fluent Bit, Vector, rsyslog omfwd) manda NDJSON grezzo con
        `Content-Type: application/x-ndjson`, e senza questa normalizzazione la
        sorgente risulterebbe "non riconosciuta" pur essendo perfettamente
        valida.
        """
        if isinstance(payload, (bytes, bytearray, memoryview)):
            payload = bytes(payload).decode("utf-8", errors="replace")
        meta = dict(meta or {})
        meta.setdefault("source", source)
        explicit = self.get(source)
        if explicit is not None:
            return self._run(explicit, payload, meta, detected_by="source")
        return self._parse_auto(source, payload, meta)

    # ── interni ─────────────────────────────────────────────────────────────
    @staticmethod
    def _run(parser: Parser, payload: Any, meta: Dict[str, Any],
             detected_by: str) -> ParseResult:
        try:
            events = parser.parse(payload, meta)
        except ParserError as exc:
            return ParseResult(parser=parser.name, errors=[f"{parser.name}: {exc}"],
                               detected_by=detected_by)
        except Exception as exc:  # un bug di parser non deve abbattere l'API
            return ParseResult(parser=parser.name,
                               errors=[f"{parser.name}: internal error: {exc}"],
                               detected_by=detected_by)
        return ParseResult(events=list(events), parser=parser.name,
                           detected_by=detected_by)

    def _parse_auto(self, source: str, payload: Any,
                    meta: Dict[str, Any]) -> ParseResult:
        parser = self.detect(payload, meta)
        if parser is not None:
            result = self._run(parser, payload, meta, detected_by="auto")
            result.parser = result.parser or parser.name
            return result

        # Payload misto: detection riga per riga (bounded). Copre il caso reale
        # di un relay rsyslog che inoltra sorgenti diverse sullo stesso canale.
        if not isinstance(payload, str) or "\n" not in payload.strip():
            return ParseResult(errors=[f"no parser matched source={source!r}"],
                               detected_by="auto")
        merged = ParseResult(detected_by="auto-line")
        used: Dict[str, int] = {}
        for index, line in enumerate(payload.splitlines()):
            if index >= MAX_AUTO_LINES:
                merged.unparsed += len(payload.splitlines()) - index
                break
            line = line.strip()
            if not line:
                continue
            line_parser = self.detect(line, meta)
            if line_parser is None:
                merged.unparsed += 1
                continue
            single = self._run(line_parser, line, meta, detected_by="auto-line")
            if single.events:
                merged.events.extend(single.events)
                used[line_parser.name] = used.get(line_parser.name, 0) + len(single.events)
            else:
                merged.unparsed += 1
                merged.errors.extend(single.errors[:1])
        if used:
            top = max(used.items(), key=lambda kv: kv[1])[0]
            merged.parser = top if len(used) == 1 else "mixed:" + ",".join(sorted(used))
        elif not merged.errors:
            merged.errors.append(f"no parser matched source={source!r}")
        return merged


def _build_default_registry() -> ParserRegistry:
    registry = ParserRegistry()
    # Ordine di auto-detection: specifici → generici.
    registry.register(WindowsEventParser(), aliases=("win_event", "winevent", "evtx"))
    registry.register(SuricataParser(), aliases=("eve", "ids"))
    registry.register(ZeekParser(), aliases=("bro",))
    registry.register(FirewallParser("pfsense"), aliases=("opnsense", "filterlog"))
    registry.register(FirewallParser("pfirewall"), aliases=("windows_firewall",))
    registry.register(FirewallParser("iptables"), aliases=("ufw",))
    registry.register(WebProxyParser("squid"))
    registry.register(WebProxyParser("nginx"), aliases=("apache", "httpd", "access_log"))
    registry.register(SyslogParser(), aliases=("rfc5424", "rfc3164"))
    registry.register(FirewallParser("firewall"))
    registry.register(WebProxyParser("web"))
    registry.register(JsonGenericParser(), aliases=("ndjson", "generic"), generic=True)
    return registry


default_registry = _build_default_registry()


def parser_catalog() -> List[Tuple[str, str]]:
    """(nome, source_type) per la UI: quali sorgenti sono supportate."""
    seen = set()
    out: List[Tuple[str, str]] = []
    for name in default_registry.names():
        parser = default_registry.get(name)
        if parser is None or parser.name in seen:
            continue
        seen.add(parser.name)
        out.append((parser.name, parser.source_type))
    return out
