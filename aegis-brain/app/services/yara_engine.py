"""Motore YARA lato brain per Aegis Total (sandbox statica).

Perché qui: Aegis Total ha già PE/entropia/packer/import/IOC — il pezzo che
mancava è la scansione con firme del SOC (tabella yara_rules) sul campione
caricato. Con le firme YARA attive, un upload può diventare "malicious" per
fatto (match) e non solo per euristica.

Fail-soft: se yara-python non è installato o le regole non compilano, il
risultato lo DICE (enabled=False + motivo) invece di fingere scansioni
andate a buon fine. Ogni regola viene compilata singolarmente: una regola
rotta del SOC non deve mettere ko tutte le altre.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.core.logging import get_logger

logger = get_logger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
    YARA_IMPORT_ERROR: Optional[str] = None
except Exception as _exc:  # pragma: no cover - dipende dall'ambiente
    YARA_AVAILABLE = False
    YARA_IMPORT_ERROR = str(_exc)

MAX_SCAN_BYTES = 32 * 1024 * 1024  # tetto: sopra, skip dichiarato

# Peso di un match in base alla severity della regola. Le regole manuali
# storiche non avevano severity: il default resta "high" e il punteggio non
# cambia per loro (40), mentre un feed può distinguere critical/high/medium/low.
SEVERITY_SCORE = {"low": 10, "medium": 25, "high": 40, "critical": 60}


def compile_rules(rules: List[Tuple[str, str]]) -> Tuple[List[Tuple[str, Any]], List[Dict[str, str]]]:
    """Compila ogni regola singolarmente.

    Ritorna ([(nome, compilata), ...], errori): il nome viaggia con la
    regola compilata, così il chiamante non deve ripetere pairing fragili
    con zip. Una regola con sintassi invalida non blocca le altre — è la
    differenza tra un motore e un giocattolo fragile.
    """
    ok: List[Tuple[str, Any]] = []
    errors: List[Dict[str, str]] = []
    if not YARA_AVAILABLE:
        return ok, [{"rule": "*", "error": f"yara-python non installato: {YARA_IMPORT_ERROR}"}]
    for name, content in rules:
        try:
            ok.append((name, yara.compile(source=content)))
        except Exception as exc:
            errors.append({"rule": name, "error": str(exc)[:300]})
    return ok, errors


def scan_bytes(data: bytes, compiled_rules: List[Tuple[str, Any]],
               metadata: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Scansiona il buffer con le regole compilate. Mai eccezioni.

    `metadata` è opzionale e indicizzato per il nome della regola nel DB:
    aggiunge severity/tags/description/MITRE al match senza cambiare la
    firma usata dai test e dagli agenti.
    """
    metadata = metadata or {}
    out: Dict[str, Any] = {"enabled": YARA_AVAILABLE and bool(compiled_rules),
                           "matches": [], "errors": [], "skipped": False}
    if not out["enabled"]:
        return out
    if len(data) > MAX_SCAN_BYTES:
        out["skipped"] = True
        out["errors"] = [{"rule": "*", "error": f"file oltre {MAX_SCAN_BYTES // (1024 * 1024)}MB: skip dichiarato"}]
        return out
    matches: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for name, compiled in compiled_rules:
        try:
            meta = metadata.get(name) or {}
            for m in compiled.match(data=data):
                strings = []
                try:
                    for s in m.strings:
                        # yara-python 4.x: StringMatch con .identifier/.instances
                        ident = getattr(s, "identifier", None) or getattr(s, "name", "")
                        strings.append(str(ident))
                except Exception:
                    pass
                matches.append({
                    "rule": m.rule,
                    "rule_name": name,
                    "strings": strings[:10],
                    "severity": meta.get("severity") or "high",
                    "description": meta.get("description"),
                    "mitre": meta.get("mitre"),
                    "tags": meta.get("tags") or [],
                    "source": meta.get("source") or "manual",
                })
        except Exception as exc:
            errors.append({"rule": name, "error": str(exc)[:200]})
    out["matches"] = matches
    out["errors"] = errors
    return out


def score_impact(scan_result: Dict[str, Any], current_score: int) -> Tuple[int, List[Dict[str, Any]]]:
    """I match YARA alzano lo score (un match = fatto, non indizio).

    Un finding per match. Il peso segue la severity della regola; il default
    `high` preserva il comportamento delle regole manuali pre-feed.
    """
    findings: List[Dict[str, Any]] = []
    score = current_score
    for m in scan_result.get("matches", []):
        severity = str(m.get("severity") or "high").lower()
        weight = SEVERITY_SCORE.get(severity, SEVERITY_SCORE["high"])
        score += weight
        finding = {
            "type": "yara_signature_match",
            "severity": severity,
            "score": weight,
            "detail": f"YARA rule '{m['rule']}' (source: {m['rule_name']}) matched the sample",
            "rule_name": m["rule"],
            "source": m.get("source") or "manual",
        }
        if m.get("description"):
            finding["description"] = m["description"]
        if m.get("mitre"):
            finding["mitre"] = m["mitre"]
        if m.get("tags"):
            finding["tags"] = m["tags"]
        findings.append(finding)
    return min(score, 100), findings
