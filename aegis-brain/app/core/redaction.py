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

CONTROL_TAG = "stripped-ctrl"

# Caratteri di controllo che un database testuale non puo' rappresentare.
# TAB (0x09), LF (0x0a) e CR (0x0d) sono esclusi: sono legittimi in una
# command line e nei log.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_control_chars(value: str, stripped: set | None = None) -> str:
    """Rimuove i caratteri di controllo non memorizzabili (§ NUL).

    Perche' non e' cosmetico: PostgreSQL rifiuta 0x00 in un campo text
    (invalid byte sequence for encoding "UTF8: 0x00"), quindi basta un NUL in
    un nome processo per far fallire la scrittura dell'evento. E il fallimento
    non restava contenuto: nell'ingestion batch scattava l'error path, che
    toccava un oggetto ORM scaduto prima del rollback e sollevava
    PendingRollbackError -> 500. Un evento cosi' avvelenava l'intero batch, e
    l'outbox dell'agente lo rigioca: la telemetria dell'endpoint si fermava in
    silenzio. Un NUL non e' informazione (non esiste rappresentazione possibile
    per quel valore), quindi rimuoverlo non cambia il significato dell'evento:
    qui si rimuove e lo si DICHIARA in `quality`.
    """
    if not _CONTROL_CHARS.search(value):
        return value
    if stripped is not None:
        stripped.add(CONTROL_TAG)
    return _CONTROL_CHARS.sub("", value)


def sanitize_event(payload: dict) -> dict:
    """Rende sicuro un payload evento prima della persistenza (audit: ricorsivo).

    Redige command_line e TUTTE le stringhe annidate (processes/users/
    network_flows/details/capabilities compresi) e rimuove i caratteri di
    controllo non memorizzabili. Non tocca gli identificatori operativi
    necessari al SOC (agent_id/timestamp/event_type/hostname/ip_address/os/
    process_name/user/pid).
    """
    stripped: set[str] = set()
    clean = _sanitize_value("", payload, stripped)
    if stripped and isinstance(clean, dict):
        # Stessa convenzione del troncamento: la perdita si dichiara, non si
        # nasconde. Un evento alterato e' visibile a chi indaga.
        marker = ":".join(sorted(stripped))
        existing = clean.get("quality")
        merged = f"{existing};{marker}" if existing else marker
        clean["quality"] = merged[:64]  # max_length dichiarato dal campo
    return clean


_PASSTHROUGH_KEYS = frozenset({
    "agent_id", "agentId", "timestamp", "event_type", "eventType",
    "hostname", "ip_address", "ipAddress", "os", "process_name",
    "processName", "user", "pid", "parent_pid", "parentPid",
    "parent_process_name", "parentProcessName",
})


def _sanitize_value(key: str, value, stripped: set | None = None):
    if isinstance(value, dict):
        return {k: _sanitize_value(k, v, stripped) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(key, v, stripped) for v in value]
    if isinstance(value, str):
        # Anche i campi passthrough (nomi processo, hostname, utente): un NUL
        # li' non e' meno fatale che altrove. Il carattere si toglie PRIMA di
        # distinguere il tipo di campo, cosi' non esiste un ramo che lo lasci
        # passare.
        value = strip_control_chars(value, stripped)
    if not isinstance(value, str):
        return value
    if key in _PASSTHROUGH_KEYS:
        return value
    if key.lower() in ("command_line", "commandline"):
        return redact_text(value)
    return redact_value(key, value)