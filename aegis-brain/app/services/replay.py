"""Replay engine deterministico + KPI detection (M4 Fase 5).

Esegue le regole statiche su eventi fissi (corpus versionato), senza DB né
rete né tempo: stesso input → stesso output, ovunque. Usato da
POST /rules/replay e dai test. MTTD/triage si misurano solo live (pilot):
qui il report li dichiara non misurabili invece di inventarli.
"""
import json
import os
from typing import Any, Dict, List, Optional

from app.api.schemas.common import EventSchema
from app.rules.rule_definitions import (
    STATIC_RULES, ALL_RULES, stamp_result, is_canary_rule,
)

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "corpus")
# Il corpus rappresenta ~1 host-day di attività mista: la stima
# falsi-positivi/host/giorno è onesta solo a questa assunzione documentata.
CORPUS_HOST_DAYS = 1.0
DATASET_VERSION = "corpus-v1"


def run_static_replay(
    events: List[Dict[str, Any]],
    include_canary: bool = False,
    seed: int | None = None,
) -> Dict[str, Any]:
    """Esegue ALL_RULES su ogni evento. Ritorna hits + scarti + canary.

    Deterministico: ordine regole = STATIC_RULES, niente random, niente I/O.
    Eventi non validi per EventSchema: contati in `invalid`, mai eccezioni.
    Se viene passato `seed`, l'ordine di esecuzione è una permutazione
    riproducibile dallo stesso seed (es. risposta a "quanto è robusto a
    eventi fuori ordine") — mai random non seedato.
    """
    if seed is not None:
        import random
        rng = random.Random(seed)
        events = list(events)
        rng.shuffle(events)
    hits: List[Dict[str, Any]] = []
    canary_hits: List[Dict[str, Any]] = []
    invalid = 0
    for index, raw in enumerate(events):
        try:
            event = EventSchema(**(raw.get("event") if isinstance(raw, dict) and "event" in raw else raw))
        except Exception:
            invalid += 1
            continue
        for rule_fn in ALL_RULES:
            try:
                res = rule_fn(event)
            except Exception:
                continue
            if not res.triggered:
                continue
            stamp_result(rule_fn, res)
            entry = {
                "index": index,
                "rule_id": res.rule_id,
                "version": res.version,
                "severity": res.severity,
                "confidence": res.confidence,
                "description": res.description,
                "mitre_technique_id": res.mitre_technique_id,
            }
            if is_canary_rule(res.rule_id):
                if include_canary:
                    canary_hits.append(entry)
            else:
                hits.append(entry)
    return {"hits": hits, "canary_hits": canary_hits, "invalid": invalid,
            "events": len(events)}


def _load_corpus(name: str) -> List[Dict[str, Any]]:
    path = os.path.join(CORPUS_DIR, name)
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _load_corpus_tolerant(name: str) -> tuple[List[Dict[str, Any]], int]:
    """Come _load_corpus ma conta le righe non-JSON senza alzare eccezioni:
    il corpus «malformed» DEVE contenere anche roba non parseabile."""
    path = os.path.join(CORPUS_DIR, name)
    out = []
    invalid = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                invalid += 1
    return out, invalid


def _prf(tp: int, fp: int, fn: int) -> Dict[str, Optional[float]]:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def score_corpus(
    benign: Optional[List[Dict[str, Any]]] = None,
    suspicious: Optional[List[Dict[str, Any]]] = None,
    malformed: Optional[List[Dict[str, Any]]] = None,
    host_days: float = CORPUS_HOST_DAYS,
    include_canary: bool = False,
    seed: int | None = None,
) -> Dict[str, Any]:
    """TP = riga sospetta con almeno una regola attesa tra gli hit;
    FN = riga sospetta senza hit attesi; FP = riga benigna con hit.
    Hit extra su righe sospette: informativi, non penalizzati.
    «malformed»: righe corrotte/incomplete che il pipeline deve scartare
    contandole come invalid (mai eccezioni, mai crash).
    """
    if benign is None:
        benign = _load_corpus("benign.jsonl")
    if suspicious is None:
        suspicious = _load_corpus("suspicious.jsonl")
    _malformed, _malformed_nonjson = (malformed, 0) if malformed is not None \
        else _load_corpus_tolerant("malformed.jsonl")

    per_rule: Dict[str, Dict[str, int]] = {}
    for s in STATIC_RULES:
        per_rule[s.rule_id] = {"tp": 0, "fp": 0, "fn": 0, "name": s.name}

    fp = 0
    for raw in benign:
        rep = run_static_replay([raw], include_canary=include_canary, seed=seed)
        for h in rep["hits"]:
            fp += 1
            if h["rule_id"] in per_rule:
                per_rule[h["rule_id"]]["fp"] += 1

    tp = fn = 0
    fn_lines: List[int] = []
    for i, raw in enumerate(suspicious):
        expect = {str(x).upper() for x in (raw.get("expect") or [])}
        rep = run_static_replay([raw], include_canary=include_canary, seed=seed)
        got = {h["rule_id"].upper() for h in rep["hits"]}
        if expect & got:
            tp += 1
            for rid in expect & got:
                if rid in per_rule:
                    per_rule[rid]["tp"] += 1
        else:
            fn += 1
            fn_lines.append(i)
            for rid in expect:
                if rid in per_rule:
                    per_rule[rid]["fn"] += 1

    invalid_total = _malformed_nonjson
    for raw in _malformed:
        rep = run_static_replay([raw], include_canary=include_canary, seed=seed)
        invalid_total += rep["invalid"]

    overall = _prf(tp, fp, fn)
    per_rule_out = {
        rid: {"name": v["name"], **_prf(v["tp"], v["fp"], v["fn"]),
              "tp": v["tp"], "fp": v["fp"], "fn": v["fn"]}
        for rid, v in per_rule.items()
    }
    return {
        "engine": "static-replay-v1",
        "dataset_version": DATASET_VERSION,
        "seed": seed,
        "rules": len(STATIC_RULES),
        "benign_lines": len(benign),
        "suspicious_lines": len(suspicious),
        "malformed_lines": len(_malformed) + _malformed_nonjson,
        "malformed_invalid": invalid_total,
        "tp": tp, "fp": fp, "fn": fn,
        **overall,
        "false_positives_per_host_day": (fp / host_days) if host_days else None,
        "host_days_assumption": host_days,
        "fn_line_indexes": fn_lines,
        "per_rule": per_rule_out,
        # Misurabili solo live con timestamp reali (pilot, Fase 10).
        "mttd_seconds": None,
        "triage_seconds": None,
        "mttd_note": "not measurable in replay; measured live from alert timestamps",
    }
