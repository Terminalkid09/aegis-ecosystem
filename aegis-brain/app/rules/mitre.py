"""Tattiche e tecniche MITRE ATT&CK referenziate dalle regole in bundle.

Perché una tabella e non un campo nelle regole: lo schema Sigma non ha un campo
per il **nome** leggibile della tecnica, ha solo i tag `attack.tXXXX`. Dal tag
si ricava l'id (es. `T1110.001`); il nome lo si prende da qui.

Perché la tabella è corta di proposito: copre **solo** le tecniche citate dalle
regole incluse. Se una regola della community cita una tecnica non presente, il
nome resta `None` — meglio un campo vuoto che un nome inventato. Lo *id* c'è
sempre, ed è quello che serve al filtro e all'export OCSF.

Nota storica: prima di questo modulo `mitre_technique_name` veniva riempito con
il **titolo della regola**, quindi un alert mostrava `T1110.001 SSH
Authentication Failure` — cioè il nome della regola al posto del nome della
tecnica ("Password Guessing"). Il titolo della regola è già nella `description`.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

# 14 tattiche Enterprise: tag Sigma (`attack.<nome>`) → (id, nome canonico).
# `attack.mitre` è un marcatore di collezione, non una tattica: non è qui, e
# viene semplicemente ignorato.
TACTICS: Dict[str, Tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource_development": ("TA0042", "Resource Development"),
    "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "command_and_control": ("TA0011", "Command and Control"),
    "impact": ("TA0040", "Impact"),
}

# Nomi canonici per le tecniche usate dalle regole in bundle.
TECHNIQUES: Dict[str, str] = {
    "T1027": "Obfuscated Files or Information",
    "T1046": "Network Service Discovery",
    "T1053.005": "Scheduled Task",
    "T1059.001": "PowerShell",
    "T1070.001": "Clear Windows Event Logs",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1078": "Valid Accounts",
    "T1078.003": "Local Accounts",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1204.002": "Malicious File",
    "T1543.003": "Windows Service",
}


def tactic_from_tags(tags: Optional[Iterable[str]]) -> Optional[Tuple[str, str]]:
    """Prima tattica riconosciuta tra i tag `attack.<nome>`.

    Una regola può avere più tag (una sequenza credential_access → initial_access
    ne ha due): si prende la prima, che è quella che descrive il trigger.
    """
    for tag in tags or []:
        name = str(tag).strip().lower()
        if name.startswith("attack."):
            hit = TACTICS.get(name.split(".", 1)[1])
            if hit:
                return hit
    return None


def technique_name(technique_id: Optional[str]) -> Optional[str]:
    """Nome canonico della tecnica, o `None` se non è nella tabella."""
    if not technique_id:
        return None
    return TECHNIQUES.get(str(technique_id).strip().upper())


def technique_names(technique_ids: Optional[Iterable[str]]) -> List[str]:
    """Nomi noti di una lista di tecniche (le sconosciute si saltano)."""
    return [name for name in (technique_name(t) for t in technique_ids or []) if name]
