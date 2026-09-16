"""Correlazione multi-evento: threshold e sequence.

Perché esiste: la maggior parte degli attacchi reali non è un singolo evento
straordinario ma una **sequenza** di eventi normali. Cinque logon falliti di
fila non sono cinque incidenti: sono un brute force. Un successo dopo cinque
fallimenti è un accesso riuscito dopo un brute force — e quello è un incidente
vero. Nessuna regola su singolo evento può vederlo.

Implementazione:
- `threshold`: N eventi che soddisfano un match, nello stesso gruppo, in una
  finestra temporale;
- `sequence`: lo step A deve raggiungere `count` volte, poi lo step B deve
  verificarsi entro la finestra.

Lo stato vive in Redis (contatori con TTL = finestra): niente tabelle di stato,
niente job di pulizia, e il costo è O(1) per evento. Se Redis è giù il motore
non emette falsi positivi e non blocca l'ingestione: salta la valutazione e lo
registra.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

import redis.asyncio as redis_lib
import yaml

from app.core.config import settings
from app.core.logging import get_logger
from app.ingest.base import UnifiedEvent
from app.rules.sigma.fields import get_values, has_field
from app.rules.sigma.matcher import compile_field_match

logger = get_logger(__name__)
rc = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                 "rules", "correlation")

SUPPORTED_TYPES = ("threshold", "sequence")


@dataclass
class CorrelationRule:
    id: str
    title: str
    type: str
    group_by: List[str] = field(default_factory=list)
    threshold: int = 5
    window_seconds: int = 300
    severity: str = "MEDIUM"
    description: str = ""
    mitre: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source_types: List[str] = field(default_factory=list)
    match: Dict[str, Any] = field(default_factory=dict)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    _matchers: List[Callable[[Any], bool]] = field(default_factory=list, repr=False)
    unsupported: List[str] = field(default_factory=list)

    @property
    def executable(self) -> bool:
        return not self.unsupported and bool(self._matchers)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "type": self.type,
            "group_by": self.group_by, "threshold": self.threshold,
            "window_seconds": self.window_seconds, "severity": self.severity,
            "mitre": self.mitre, "steps": len(self.steps),
            "source_types": self.source_types, "description": self.description,
            "executable": self.executable, "unsupported": self.unsupported,
        }


@dataclass
class CorrelationMatch:
    rule_id: str
    title: str
    severity: str
    description: str
    mitre: List[str]
    group_key: str
    group_label: str
    observed: int
    window_seconds: int
    # Tag della regola: servono a chi costruisce l'alert per ricavare la
    # tattica MITRE (`attack.credential_access` → TA0006). Senza, l'alert di
    # correlazione perdeva la tattica che l'alert Sigma invece riportava.
    tags: List[str] = field(default_factory=list)
    event: Optional[UnifiedEvent] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "description": self.description, "mitre_techniques": self.mitre,
            "group_key": self.group_key, "group": self.group_label,
            "observed": self.observed, "window_seconds": self.window_seconds,
            "engine": "correlation", "type": "sequence" if self.group_label else "threshold",
        }


def _compile_match(spec: Dict[str, Any]) -> tuple[Optional[Callable[[Any], bool]], List[str]]:
    """Compila un blocco `match` (stessa sintassi di una selection Sigma)."""
    if not isinstance(spec, dict) or not spec:
        return None, ["empty match block"]
    predicates: List[Callable[[Any], bool]] = []
    problems: List[str] = []
    for raw_field, patterns in spec.items():
        field_name = str(raw_field)
        if "|" in field_name:
            name, *modifiers = field_name.split("|")
        else:
            name, modifiers = field_name, []
        predicate, issues = compile_field_match(name.strip(), modifiers, patterns,
                                                get_values, has_field)
        if issues:
            problems.extend(f"{raw_field}: {i}" for i in issues)
            continue
        if predicate is not None:
            predicates.append(predicate)
    if problems:
        return None, problems
    if not predicates:
        return None, ["match without usable fields"]

    def combined(event: Any) -> bool:
        return all(p(event) for p in predicates)

    return combined, []


def load_correlation_rules(directory: Optional[str] = None) -> List[CorrelationRule]:
    rules: List[CorrelationRule] = []
    base = directory or DEFAULT_RULES_DIR
    if not os.path.isdir(base):
        return rules
    for name in sorted(os.listdir(base)):
        if not name.lower().endswith((".yml", ".yaml")):
            continue
        try:
            with open(os.path.join(base, name), encoding="utf-8") as fh:
                documents = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError) as exc:
            logger.warning(f"Regola di correlazione non leggibile ({name}): {exc}")
            continue
        for doc in documents:
            items = doc if isinstance(doc, list) else [doc]
            for item in items:
                rule = _build_rule(item, name)
                if rule is not None:
                    rules.append(rule)
    return rules


def _build_rule(doc: Any, filename: str) -> Optional[CorrelationRule]:
    if not isinstance(doc, dict) or not doc.get("title"):
        return None
    rtype = str(doc.get("type", "")).strip().lower()
    unsupported: List[str] = []
    if rtype not in SUPPORTED_TYPES:
        unsupported.append(f"unsupported correlation type: {rtype or 'missing'}")
    matchers: List[Callable[[Any], bool]] = []
    if rtype == "threshold":
        matcher, problems = _compile_match(doc.get("match") or {})
        unsupported.extend(problems)
        if matcher:
            matchers.append(matcher)
    elif rtype == "sequence":
        steps = doc.get("steps") or []
        if not isinstance(steps, list) or len(steps) < 2:
            unsupported.append("sequence requires at least 2 steps")
        for step in steps if isinstance(steps, list) else []:
            matcher, problems = _compile_match((step or {}).get("match") or {})
            unsupported.extend(problems)
            matchers.append(matcher if matcher else (lambda _e: False))
    rule_id = str(doc.get("id") or "")
    if not rule_id:
        rule_id = "corr-" + hashlib.sha256(str(doc.get("title")).encode()).hexdigest()[:12]
    return CorrelationRule(
        id=rule_id,
        title=str(doc["title"]),
        type=rtype,
        group_by=[str(g) for g in (doc.get("group_by") or [])][:4],
        threshold=max(1, int(doc.get("threshold", 5) or 5)),
        window_seconds=max(1, int(doc.get("window_seconds", 300) or 300)),
        severity=str(doc.get("severity", "MEDIUM")).upper(),
        description=str(doc.get("description", "") or ""),
        mitre=[str(t).upper() for t in (doc.get("mitre") or [])][:6],
        tags=[str(t) for t in (doc.get("tags") or [])][:20],
        source_types=[str(s).lower() for s in (doc.get("source_types") or [])],
        match=doc.get("match") or {},
        steps=doc.get("steps") or [],
        _matchers=matchers,
        unsupported=unsupported,
    )


class CorrelationEngine:
    def __init__(self, directory: Optional[str] = None):
        self.directory = directory or DEFAULT_RULES_DIR
        self._rules: List[CorrelationRule] = []
        self.reload()

    def reload(self) -> int:
        self._rules = load_correlation_rules(self.directory)
        return len(self._rules)

    def rules(self) -> List[CorrelationRule]:
        return list(self._rules)

    def executable_rules(self) -> List[CorrelationRule]:
        return [r for r in self._rules if r.executable]

    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    @staticmethod
    def _group_key(rule: CorrelationRule, event: UnifiedEvent) -> tuple:
        """Chiave di raggruppamento (es. src_ip). Vuoto → regola non applicabile."""
        parts = []
        for field_name in rule.group_by:
            values = get_values(event, field_name)
            if not values:
                return ("", False)
            parts.append(str(values[0])[:128])
        if not parts:
            return ("global", True)
        return ("|".join(parts), True)

    def _source_matches(self, rule: CorrelationRule, event: UnifiedEvent) -> bool:
        if not rule.source_types:
            return True
        return (event.source_type or "").lower() in rule.source_types

    async def evaluate(self, events: Sequence[UnifiedEvent]) -> List[CorrelationMatch]:
        """Valuta gli eventi contro le regole. Non solleva mai."""
        matches: List[CorrelationMatch] = []
        rules = self.executable_rules()
        if not rules:
            return matches
        for event in events:
            for rule in rules:
                if not self._source_matches(rule, event):
                    continue
                try:
                    if rule.type == "threshold":
                        match = await self._eval_threshold(rule, event, 0)
                    else:
                        match = await self._eval_sequence(rule, event)
                except Exception as exc:
                    logger.warning(f"Correlazione {rule.id} non valutata: {exc}")
                    continue
                if match is not None:
                    matches.append(match)
        return matches

    async def _eval_threshold(self, rule: CorrelationRule, event: UnifiedEvent,
                              step_index: int) -> Optional[CorrelationMatch]:
        matcher = rule._matchers[step_index]
        if not matcher(event):
            return None
        group_key, ok = self._group_key(rule, event)
        if not ok:
            return None
        counter_key = f"corr:{rule.id}:{group_key}:{step_index}"
        count = await rc.incr(counter_key)
        if count == 1:
            await rc.expire(counter_key, rule.window_seconds)
        if count < rule.threshold:
            return None
        # Fire-once per finestra: senza questa chiave un attacco lungo
        # genererebbe un alert a ogni evento oltre la soglia.
        claimed = await rc.set(f"corr-fired:{rule.id}:{group_key}:{step_index}",
                               "1", ex=rule.window_seconds, nx=True)
        if not claimed:
            return None
        return CorrelationMatch(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            description=rule.description, mitre=rule.mitre, tags=rule.tags,
            group_key=group_key, group_label=self._label(rule, event),
            observed=count, window_seconds=rule.window_seconds, event=event,
        )

    async def _eval_sequence(self, rule: CorrelationRule, event: UnifiedEvent) -> Optional[CorrelationMatch]:
        """Ogni step accumula i propri conteggi; il trigger è l'ultimo step."""
        group_key, ok = self._group_key(rule, event)
        if not ok:
            return None
        last_index = len(rule._matchers) - 1
        for index, matcher in enumerate(rule._matchers):
            if not matcher(event):
                continue
            if index == last_index:
                # L'ultimo step scatta solo se il precedente è "armato".
                armed_key = f"corr-armed:{rule.id}:{group_key}:{index - 1}"
                if await rc.get(armed_key):
                    claimed = await rc.set(f"corr-fired:{rule.id}:{group_key}:seq",
                                           "1", ex=rule.window_seconds, nx=True)
                    if not claimed:
                        return None
                    return CorrelationMatch(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        description=rule.description, mitre=rule.mitre, tags=rule.tags,
                        group_key=group_key, group_label=self._label(rule, event),
                        observed=len(rule._matchers), window_seconds=rule.window_seconds,
                        event=event,
                    )
                continue
            needed = int((rule.steps[index] or {}).get("count", 1) or 1)
            counter_key = f"corr:{rule.id}:{group_key}:{index}"
            count = await rc.incr(counter_key)
            if count == 1:
                await rc.expire(counter_key, rule.window_seconds)
            if count >= needed:
                await rc.set(f"corr-armed:{rule.id}:{group_key}:{index}", "1",
                             ex=rule.window_seconds)
        return None

    @staticmethod
    def _label(rule: CorrelationRule, event: UnifiedEvent) -> str:
        """Descrizione leggibile del gruppo che ha scatenato la regola."""
        try:
            return "|".join(str(get_values(event, f)[0]) for f in rule.group_by if get_values(event, f))
        except Exception:
            return ""

    def coverage(self) -> Dict[str, Any]:
        rules = self.rules()
        executable = [r for r in rules if r.executable]
        techniques: set = set()
        for rule in executable:
            techniques.update(rule.mitre)
        return {
            "engine": "correlation",
            "directory": os.path.basename(self.directory),
            "rules_total": len(rules),
            "rules_executable": len(executable),
            "by_type": {t: sum(1 for r in executable if r.type == t)
                        for t in SUPPORTED_TYPES},
            "mitre_techniques": sorted(techniques),
            "excluded": [{"id": r.id, "title": r.title, "reason": r.unsupported}
                         for r in rules if not r.executable],
        }


_engine: Optional[CorrelationEngine] = None


def get_correlation_engine(directory: Optional[str] = None) -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine(directory)
    return _engine
