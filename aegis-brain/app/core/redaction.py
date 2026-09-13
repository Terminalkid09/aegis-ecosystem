"""Redazione di segreti da campi evento (Fase 2).

Difesa in profondità: la redazione reale avviene sul sensore, ma il server
deve comunque non persistere token/password/cookie/chiavi che arrivino nella
command line o in campi stringa. Deterministico, veloce e testabile.

Pattern coperti: --password/--pass/--token/--secret/--api-key/--cookie/
--auth, Bearer/Token/ApiKey header, chiavi AWS (AKIA/AWS_SECRET), valori
chiave=valore per password/token/secret, variabili di ambiente in cmd.
"""
import re

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)(--?(pass(word)?|pwd|token|secret|api[-_]?key|salt|auth|session[-_]?cookie)\s*[=:\s])(\S+)"), r"\1<redacted>"),
    (re.compile(r"(?i)(bearer\s+)([^\s\"']+)"), r"\1<redacted>"),
    (re.compile(r"""(?i)(["']?(?:password|passwd|pwd|token|secret|api[-_]?key|authorization|cookie)["']?\s*[=:]\s*["']?)(\S+)"""), r"\1<redacted>"),
    (re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)([A-Za-z0-9/+=]+)"), r"\1<redacted>"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "<redacted>"),
    (re.compile(r"(?i)(x-oxo-shell\s+)([A-Za-z0-9\-])\S*"), r"\1<redacted>"),
    (re.compile(r"(?i)(sk-[A-Za-z0-9]{10,})"), "<redacted>"),
    (re.compile(r"(?i)(set\s+)([A-Za-z0-9_]*?(?:pass|token|secret|key|cookie|cred)[A-Za-z0-9_]*\s*=?\s*)(\S+)"), r"\1\2<redacted>"),
    (re.compile(r"(?i)(%\w*(?:pass|token|secret|key|cookie|cred)\w*%)"), "<redacted>"),
]

def redact_text(text: str | None, max_len: int = 4096) -> str | None:
    """Redige pattern sensibili da testo. Se il testo supera max_len lo tronca."""
    if not text:
        return text
    text = text[: (max_len * 2)]  # prima un bound difensivo, poi troncamento finale
    for rx, repl in _PATTERNS:
        text = rx.sub(repl, text)
    return text[:max_len]

_SECRET_KEYS = {"password", "token", "secret", "api_key", "apikey", "key", "cookie", "auth", "credential", "pass"}

def redact_value(key: str, value):
    """Per coppie chiave/valore (es. JSON di dettaglio): offusca il valore se la
    chiave è un segreto riconosciuto (case-insensitive)."""
    if value is None:
        return value
    if not isinstance(value, str):
        return value
    k = key.lower().replace("-", "_")
    if any(s in k for s in _SECRET_KEYS):
        return "<redacted>"
    return redact_text(value)

def sanitize_event(payload: dict) -> dict:
    """Rende sicuro un payload evento prima della persistenza (audit: ricorsivo).

    Redige command_line e TUTTE le stringhe annidate (processes/users/
    network_flows/details/capabilities compresi). Non tocca gli identificatori
    operativi necessari al SOC (agent_id/timestamp/event_type/hostname/
    ip_address/os/process_name/user/pid).
    """
    return _sanitize_value("", payload)


_PASSTHROUGH_KEYS = frozenset({
    "agent_id", "agentId", "timestamp", "event_type", "eventType",
    "hostname", "ip_address", "ipAddress", "os", "process_name",
    "processName", "user", "pid", "parent_pid", "parentPid",
    "parent_process_name", "parentProcessName",
})


def _sanitize_value(key: str, value):
    if isinstance(value, dict):
        return {k: _sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(key, v) for v in value]
    if not isinstance(value, str):
        return value
    if key in _PASSTHROUGH_KEYS:
        return value
    if key.lower() in ("command_line", "commandline"):
        return redact_text(value)
    return redact_value(key, value)