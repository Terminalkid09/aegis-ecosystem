"""Raggruppamento incidenti e verdetti di correlazione (M5 Fase 6).

Funzioni pure (niente DB/Redis): raggruppano alert simili in incidenti
significativi invece di uno-per-agente, con finestre temporali configurabili.
La perdita di contesto è evitata: ogni gruppo conserva gli id degli alert.
"""
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple


def _to_ts(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        ts = value.timestamp()
        return ts
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _base_name(name: Any) -> str:
    n = (name or "").lower().strip().replace("\\", "/")
    return n.rsplit("/", 1)[-1]


def group_key(alert: Any, window_min: int = 30) -> Tuple[str, str, str, int]:
    """Chiave (agente, tecnica-o-tipo, processo, bucket temporale).

    Alert simili (stessa tecnica sullo stesso host entro la finestra) finiscono
    nello stesso incidente: niente più 1-incidente-per-agente che seppellisce
    tecniche diverse, e niente incidenti duplicati per storm dello stesso
    segnale. Bucket = epoch // finestra: deterministico e testabile.
    """
    get = (lambda k, d=None: alert.get(k, d)) if isinstance(alert, dict) else (
        lambda k, d=None: getattr(alert, k, d))
    agent = str(get("agent_id") or "unknown")
    technique = (get("mitre_technique_id") or get("event_type") or "unknown")
    technique = str(technique).upper()
    proc = _base_name(get("process_name"))
    ts = _to_ts(get("timestamp"))
    window_s = max(60, int(window_min) * 60)
    bucket = int(ts // window_s) if ts > 0 else 0
    return (agent, technique, proc, bucket)


def suggest_groups(alerts: List[Any], window_min: int = 30) -> Dict[Tuple, List[Any]]:
    """Raggruppa alert per chiave di similarità (ordine stabile)."""
    groups: Dict[Tuple, List[Any]] = defaultdict(list)
    for a in alerts:
        groups[group_key(a, window_min)].append(a)
    return dict(groups)


def group_title(key: Tuple[str, str, str, int], hostname: str = "") -> str:
    agent, technique, proc, _bucket = key
    host = hostname or agent[:8]
    return f"{technique} — {proc or 'unknown'} @ {host}"


def beacon_verdict(
    timestamps: List[float],
    min_samples: int = 5,
    max_variance: float = 5.0,
) -> Dict[str, Any]:
    """Verdetto beaconing puro: intervalli regolari = C2 probabile.

    Stessa matematica del motore Redis (media/varianza su 5+ campioni):
    estrarla qui la rende testabile senza Redis e riusabile nel replay.
    """
    ts = sorted(t for t in timestamps if t is not None)
    if len(ts) < max(2, min_samples):
        return {"beacon": False, "reason": "too-few-samples", "samples": len(ts)}
    intervals = [b - a for a, b in zip(ts, ts[1:])]
    if not intervals or any(i < 0 for i in intervals):
        return {"beacon": False, "reason": "unordered", "samples": len(ts)}
    avg = sum(intervals) / len(intervals)
    if avg <= 0:
        return {"beacon": False, "reason": "zero-interval", "samples": len(ts)}
    var = sum((i - avg) ** 2 for i in intervals) / len(intervals)
    if var < max_variance:
        return {"beacon": True, "avg_interval": avg, "variance": var,
                "samples": len(ts)}
    return {"beacon": False, "reason": "irregular", "avg_interval": avg,
            "variance": var, "samples": len(ts)}
