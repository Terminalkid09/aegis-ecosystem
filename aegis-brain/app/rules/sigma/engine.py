"""Esecuzione delle regole Sigma sugli eventi normalizzati.

La `logsource` di una regola viene **verificata**: una regola Windows non deve
girare su un log Zeek. Senza questo controllo il primo giorno in produzione
avresti migliaia di falsi positivi, ed è il motivo per cui i SIEM che
"importano Sigma" senza rispettare la logsource hanno cattiva reputazione.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional, Sequence

from app.rules.sigma.loader import DEFAULT_RULES_DIR, load_rules
from app.rules.sigma.matcher import level_to_severity
from app.rules.sigma.model import SigmaMatch, SigmaRule

# Prodotto Sigma → source_type accettati.
_PRODUCT_SOURCES = {
    "windows": {"windows_event"},
    "linux": {"syslog"},
    "zeek": {"zeek"},
    "suricata": {"suricata"},
    "webserver": {"web", "nginx", "apache", "squid"},
    "proxy": {"web", "squid", "nginx"},
    "firewall": {"firewall", "pfsense", "pfirewall", "iptables"},
    "aegis": {"json", "syslog", "windows_event", "zeek", "suricata", "web",
              "firewall", "pfsense", "pfirewall", "iptables", "nginx", "squid"},
}

# `service` Windows → sottostringa attesa nel Channel dell'evento.
_WINDOWS_SERVICE_HINTS = {
    "security": "security",
    "system": "system",
    "application": "application",
    "sysmon": "sysmon",
    "powershell": "powershell",
    "powershell-classic": "windowspowershell",
    "taskscheduler": "taskscheduler",
    "windefend": "windefend",
    "dns-server": "dns-server",
    "windows firewall": "firewall",
    "terminalservices": "terminalservices",
    "bits-client": "bits-client",
}

# `category` Windows → event_type prodotto dai nostri parser.
_WINDOWS_CATEGORY_TYPES = {
    "process_creation": {"process_creation"},
    "process_termination": {"process_termination"},
    "network_connection": {"network_connect"},
    "file_creation": {"file_created"},
    "file_event": {"file_created", "file_transfer"},
    "registry_set": {"registry_set"},
    "registry_event": {"registry_set", "registry_delete"},
    "service_installation": {"service_installed"},
    "driver_load": {"service_installed"},
    "scheduled_task": {"scheduled_task_created", "scheduled_task_updated"},
    "logon": {"auth_success", "auth_failure"},
    "log_cleared": {"log_cleared"},
    "ps_script": {"powershell_script_block", "powershell_module"},
    "dns_query": {"dns_query"},
}

# `service` per log non-Windows (Zeek/Suricata) → valore atteso.
_NETWORK_SERVICE_HINTS = {
    "dns": {"dns_query", "dns"},
    "http": {"http_request", "http"},
    "ssl": {"tls_handshake", "ssl"},
    "conn": {"network_connect", "network_denied", "conn"},
    "ssh": {"auth", "ssh"},
    "alert": {"alert", "ids_notice"},
    "notice": {"ids_notice"},
}


class SigmaEngine:
    def __init__(self, directory: Optional[str] = None):
        self.directory = directory or DEFAULT_RULES_DIR
        self._rules: List[SigmaRule] = []
        self._lock = threading.Lock()
        self.reload()

    # ── caricamento ─────────────────────────────────────────────────────────
    def reload(self) -> int:
        rules = load_rules(self.directory)
        with self._lock:
            self._rules = rules
        return len(rules)

    def rules(self) -> List[SigmaRule]:
        with self._lock:
            return list(self._rules)

    def executable_rules(self) -> List[SigmaRule]:
        return [r for r in self.rules() if r.executable]

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        for rule in self.rules():
            if rule.id == rule_id:
                return rule
        return None

    # ── valutazione ─────────────────────────────────────────────────────────
    def logsource_matches(self, rule: SigmaRule, event: Any) -> bool:
        """Verifica che la regola sia applicabile a questo tipo di evento."""
        ls = rule.logsource or {}
        if not ls:
            return True

        product = str(ls.get("product") or "").strip().lower()
        service = str(ls.get("service") or "").strip().lower()
        category = str(ls.get("category") or "").strip().lower()
        source_type = (event.source_type or "").lower()

        if product:
            allowed = _PRODUCT_SOURCES.get(product)
            if allowed is None:
                # Prodotto non mappato: la regola si applica solo se l'evento
                # dichiara esplicitamente quel prodotto.
                allowed = {product}
            if source_type not in allowed and product not in (
                    source_type, (event.source or "").lower()):
                return False

        event_type = str(event.extra.get("event_type") or "")
        channel = str(event.extra.get("channel") or "").lower()

        if category:
            if source_type == "windows_event":
                allowed_types = _WINDOWS_CATEGORY_TYPES.get(category)
                if allowed_types is None or event_type not in allowed_types:
                    return False
            else:
                hint = _NETWORK_SERVICE_HINTS.get(category)
                if hint is None or event_type not in hint:
                    return False

        if service:
            if source_type == "windows_event":
                hint = _WINDOWS_SERVICE_HINTS.get(service, service)
                if hint not in channel:
                    return False
            else:
                hint = _NETWORK_SERVICE_HINTS.get(service)
                values = {event_type, str(event.extra.get("service") or ""),
                          str(event.extra.get("zeek_log") or ""), source_type}
                if hint is not None:
                    if not (hint & values):
                        return False
                elif service not in values:
                    return False
        return True

    def evaluate(self, event: Any) -> List[SigmaMatch]:
        """Tutte le regole Sigma che scattano su un evento normalizzato."""
        matches: List[SigmaMatch] = []
        for rule in self.executable_rules():
            if not self.logsource_matches(rule, event):
                continue
            try:
                results = {name: pred(event) for name, pred in rule.selections.items()}
                if rule.condition and rule.condition(results):
                    matches.append(SigmaMatch(
                        rule_id=rule.id,
                        title=rule.title,
                        level=rule.level,
                        description=rule.description,
                        mitre_techniques=rule.mitre_techniques(),
                        tags=rule.tags,
                        event_id=event.event_id,
                    ))
            except Exception:
                # Un errore di valutazione su un evento non deve fermare la
                # pipeline: la regola viene saltata per quell'evento.
                continue
        return matches

    def severity_for(self, rule_id: str) -> str:
        rule = self.get_rule(rule_id)
        return level_to_severity(rule.level if rule else None)

    # ── copertura ───────────────────────────────────────────────────────────
    def coverage(self) -> Dict[str, Any]:
        rules = self.rules()
        executable = [r for r in rules if r.executable]
        by_level: Dict[str, int] = {}
        by_logsource: Dict[str, int] = {}
        techniques: set = set()
        for rule in executable:
            by_level[rule.level] = by_level.get(rule.level, 0) + 1
            key = "/".join(f"{k}={v}" for k, v in sorted(rule.logsource.items())) or "any"
            by_logsource[key] = by_logsource.get(key, 0) + 1
            techniques.update(rule.mitre_techniques())
        return {
            "engine": "sigma",
            "directory": os.path.basename(self.directory),
            "rules_total": len(rules),
            "rules_executable": len(executable),
            "rules_excluded": len(rules) - len(executable),
            "by_level": by_level,
            "by_logsource": by_logsource,
            "mitre_techniques": sorted(techniques),
            "excluded": [
                {"id": r.id, "title": r.title, "reason": r.unsupported}
                for r in rules if not r.executable
            ][:50],
        }


_engine: Optional[SigmaEngine] = None
_engine_lock = threading.Lock()


def get_engine(directory: Optional[str] = None) -> SigmaEngine:
    """Singleton del motore (la directory si può passare solo la prima volta)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = SigmaEngine(directory)
    return _engine
