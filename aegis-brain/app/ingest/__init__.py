"""Ingestion multi-sorgente: parser pluggable + normalizzazione SIEM.

Un SIEM non è definito dai suoi agenti ma dalla capacità di **ingestire log
eterogenei e normalizzarli**. Questo package è quel livello: ogni sorgente
(syslog, Windows Event Log, Zeek, Suricata, proxy, firewall, i propri agenti)
produce lo stesso tipo di evento unificato, allineato a OCSF, che entra nella
pipeline di detection già esistente.

Nessun parser assume il risultato: se non riconosce il payload restituisce un
errore esplicito, mai un evento inventato.
"""
from app.ingest.base import UnifiedEvent, Parser, ParserError, parse_timestamp, normalize_severity
from app.ingest.registry import ParserRegistry, default_registry

__all__ = [
    "UnifiedEvent",
    "Parser",
    "ParserError",
    "parse_timestamp",
    "normalize_severity",
    "ParserRegistry",
    "default_registry",
]
