"""Modello evento unificato e contratto dei parser.

Tutti i parser convertono verso `UnifiedEvent`: un singolo schema che il
motore Sigma, quello di correlazione, lo store e la ricerca conoscono. I campi
comuni sono allineati a OCSF 1.4.0 (device/actor/src_endpoint/dst_endpoint/
http_request) così che l'export OCSF resti immediato; i campi specifici della
sorgente finiscono in `extra` invece di forzare lo schema.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.services.ocsf import severity_to_ocsf

MAX_RAW_CHARS = 8192   # il raw è per debug/forensics, non è lo store primario

# Severità interne, ordinate. Qualsiasi parser deve mappare qui.
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Etichette viste nelle sorgenti reali → severità interna.
_SEVERITY_LABELS: Dict[str, str] = {
    # generiche
    "info": "INFO", "informational": "INFO", "debug": "INFO", "trace": "INFO",
    "notice": "LOW", "low": "LOW", "warning": "MEDIUM", "warn": "MEDIUM",
    "medium": "MEDIUM", "error": "HIGH", "err": "HIGH", "high": "HIGH",
    "critical": "CRITICAL", "crit": "CRITICAL", "alert": "CRITICAL",
    "emergency": "CRITICAL", "emerg": "CRITICAL", "fatal": "CRITICAL",
    "severe": "CRITICAL", "panic": "CRITICAL",
    # Zeek / Suricata / IDS
    "notset": "INFO", "unknown": "INFO",
    # Windows Event Level (1 critical, 2 error, 3 warning, 4 information, 5 verbose)
    "1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "INFO", "5": "INFO",
}

# Severità syslog numerica (RFC5424): 0 emerg … 7 debug.
_SYSLOG_SEVERITY = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "HIGH",
    4: "MEDIUM", 5: "LOW", 6: "INFO", 7: "INFO",
}
# Severità Windows Event Log (Level): 1 Critical … 5 Verbose.
_WINDOWS_SEVERITY = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "INFO", 5: "INFO"}


class ParserError(Exception):
    """Payload non riconosciuto o malformato. Mai un evento inventato."""


def normalize_severity(value: Any, *, kind: str = "label") -> str:
    """Converte qualunque etichetta/numerico di severità nella scala interna.

    `kind`: "label" (testo), "syslog" (0-7), "windows" (1-5).
    Sconosciuto → INFO, mai eccezione (una sorgente che manda un valore nuovo
    non deve fermare l'ingestione).
    """
    if value is None or value == "":
        return "INFO"
    if kind == "syslog":
        try:
            return _SYSLOG_SEVERITY.get(int(value), "INFO")
        except (TypeError, ValueError):
            return "INFO"
    if kind == "windows":
        try:
            return _WINDOWS_SEVERITY.get(int(value), "INFO")
        except (TypeError, ValueError):
            return "INFO"
    return _SEVERITY_LABELS.get(str(value).strip().lower(), "INFO")


def parse_timestamp(value: Any, *, default: Optional[datetime] = None) -> datetime:
    """Timestamp → datetime UTC. Supporta ISO8601, epoch s/ms/µs e valori Zeek.

    Una sorgente con timestamp strano non deve far fallire l'ingestione: si
    ricade su `default` (di norma "adesso") e si prosegue.
    """
    fallback = default or datetime.now(timezone.utc)
    if value is None or value == "":
        return fallback
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        v = float(value)
        if v <= 0:
            return fallback
        # µs / ms / s in base all'ordine di grandezza.
        if v >= 1e14:
            v /= 1_000_000
        elif v >= 1e11:
            v /= 1_000
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return fallback
    text = str(value).strip()
    # Zeek: 1700000000.123456
    try:
        f = float(text)
        if f > 1e8:
            return parse_timestamp(f)
    except ValueError:
        pass
    iso = text.replace("Z", "+00:00")
    # Windows Event TimeCreated: 2026-09-15T12:00:00.1234567Z (7 cifre frazionarie)
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        dt = datetime.fromisoformat(iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z"):
        try:
            dt = datetime.strptime(text[:26], fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return fallback


def _blank_to_none(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str) and not v.strip():
        return None
    return v


class UnifiedEvent(BaseModel):
    """Evento normalizzato, unico contratto tra parser e pipeline SIEM."""

    model_config = ConfigDict(extra="ignore")

    # ── identità e provenienza ──────────────────────────────────────────────
    time: datetime
    source: str                      # nome sorgente configurata (es. "win-sec-01")
    source_type: str                 # famiglia parser: syslog|windows_event|zeek|…
    event_id: str                    # chiave stabile di dedup (sha256 sorgente+raw)
    ocsf_class_uid: int = 0          # 0 = non determinato
    severity: str = "INFO"
    severity_id: int = 1             # OCSF Severity ID

    # ── attore / device (OCSF device + actor) ───────────────────────────────
    hostname: Optional[str] = None
    ip: Optional[str] = None
    user: Optional[str] = None
    user_domain: Optional[str] = None

    # ── processo / file (OCSF actor.process) ────────────────────────────────
    process_name: Optional[str] = None
    pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_pid: Optional[int] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None

    # ── rete (OCSF src_endpoint / dst_endpoint) ─────────────────────────────
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # ── applicativo ─────────────────────────────────────────────────────────
    url: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None
    domain: Optional[str] = None
    dns_query: Optional[str] = None

    # ── detection / signature della sorgente ────────────────────────────────
    signature_id: Optional[str] = None
    signature: Optional[str] = None
    category: Optional[str] = None

    # ── payload originale ───────────────────────────────────────────────────
    message: Optional[str] = None
    message_id: Optional[str] = None
    raw: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    def to_record(self) -> Dict[str, Any]:
        """Serializzazione pronta per lo store (datetime → ISO, extra JSON-safe)."""
        data = self.model_dump()
        data["time"] = self.time.isoformat()
        return data

    def searchable_text(self) -> str:
        """Testo su cui gira la ricerca libera (bounded)."""
        parts: List[str] = []
        for value in (self.message, self.command_line, self.url, self.dns_query,
                      self.file_path, self.process_path, self.user_agent,
                      self.signature, self.process_name, self.hostname):
            if value:
                parts.append(str(value))
        for k, v in self.extra.items():
            if isinstance(v, (str, int, float)):
                parts.append(f"{k}={v}")
        return " ".join(parts)[:MAX_RAW_CHARS]


class Parser(Protocol):
    """Contratto di un parser di sorgente.

    `can_parse` deve essere veloce e conservativo: se è ambiguo, meglio
    restituire False e lasciare decidere il parser generico.
    """

    name: str
    source_type: str

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool: ...

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]: ...


def make_event_id(source: str, raw: Any) -> str:
    """Chiave di dedup stabile: stessa riga dalla stessa sorgente → stesso id."""
    if isinstance(raw, (dict, list)):
        body = json.dumps(raw, sort_keys=True, default=str)
    else:
        body = str(raw)
    return hashlib.sha256(f"{source}\x00{body}".encode("utf-8", "ignore")).hexdigest()[:32]


def bounded_raw(raw: Any) -> str:
    """Stringa grezza per il campo `raw`, troncata per non gonfiare il DB."""
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    return text[:MAX_RAW_CHARS]


def finalize(event: UnifiedEvent) -> UnifiedEvent:
    """Chiude le invarianti comuni a ogni parser (severità OCSF + null puliti)."""
    event.severity = normalize_severity(event.severity) if event.severity else "INFO"
    event.severity_id = severity_to_ocsf(event.severity)
    for field_name in ("hostname", "user", "process_name", "file_path", "src_ip",
                       "dst_ip", "url", "domain", "command_line"):
        setattr(event, field_name, _blank_to_none(getattr(event, field_name)))
    return event


def as_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_protocol(value: Any) -> Optional[str]:
    """Normalizza il protocollo a una sigla OCSF-ish (tcp/udp/icmp/…)."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    mapping = {"6": "tcp", "17": "udp", "1": "icmp", "tcp": "tcp", "udp": "udp",
               "icmp": "icmp", "icmpv6": "icmp", "http": "tcp", "https": "tcp",
               "ssl": "tcp", "tls": "tcp", "dns": "udp", "ssh": "tcp"}
    return mapping.get(text, text[:16])
