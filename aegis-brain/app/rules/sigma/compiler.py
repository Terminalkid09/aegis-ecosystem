"""Compilazione di `detection` (selections) e `condition` di una regola Sigma.

Due passaggi:
1. ogni selection diventa un predicato sull'evento (AND tra campi, OR tra i
   valori di un campo, OR tra più blocchi nella lista);
2. la `condition` diventa un predicato sui risultati delle selection, con
   supporto a `and`/`or`/`not`, parentesi, `them` e quantificatori
   (`all of`, `1 of`, `2 of`, …).

Tutto ciò che non sappiamo compilare correttamente viene restituito come
`unsupported` — la regola viene esclusa, non eseguita a metà.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from app.rules.sigma.matcher import _wildcard_to_regex, compile_field_match

_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_MAX_FIELD_CHARS = 200_000   # bound su valori enormi (script block, ecc.)


def _keyword_predicate(keyword: str) -> Callable[[Any], bool]:
    regex = re.compile(_wildcard_to_regex(keyword), re.IGNORECASE | re.DOTALL)

    def predicate(event: Any) -> bool:
        haystack = f"{event.searchable_text()} {event.raw or ''}"[:_MAX_FIELD_CHARS]
        return regex.search(haystack) is not None

    return predicate


def _or(parts: Sequence[Callable[[Any], bool]]) -> Callable[[Any], bool]:
    def predicate(event: Any) -> bool:
        return any(part(event) for part in parts)
    return predicate


def _and(parts: Sequence[Callable[[Any], bool]]) -> Callable[[Any], bool]:
    def predicate(event: Any) -> bool:
        return all(part(event) for part in parts)
    return predicate


def build_selection(
    spec: Any,
    get_values: Callable[[Any, str], List[Any]],
    has_field: Callable[[Any, str], bool],
) -> Tuple[Optional[Callable[[Any], bool]], List[str]]:
    """Compila una selection. Lista vuota di unsupported = eseguibile."""
    if isinstance(spec, dict):
        predicates: List[Callable[[Any], bool]] = []
        unsupported: List[str] = []
        for raw_field, patterns in spec.items():
            raw_field = str(raw_field)
            if "|" in raw_field:
                field, *modifiers = raw_field.split("|")
            else:
                field, modifiers = raw_field, []
            if field.strip().lower() in ("", "null"):
                # Sigma: campo nullo = keyword search sul valore.
                if isinstance(patterns, list):
                    predicates.append(_or([_keyword_predicate(str(p)) for p in patterns]))
                else:
                    predicates.append(_keyword_predicate(str(patterns)))
                continue
            predicate, problems = compile_field_match(field.strip(), modifiers, patterns,
                                                      get_values, has_field)
            if problems:
                unsupported.extend(f"{raw_field}: {p}" for p in problems)
                continue
            if predicate is not None:
                predicates.append(predicate)
        if not predicates:
            return None, unsupported or ["selection without usable fields"]
        return _and(predicates), unsupported

    if isinstance(spec, list):
        parts: List[Callable[[Any], bool]] = []
        unsupported: List[str] = []
        for item in spec:
            if isinstance(item, str):
                parts.append(_keyword_predicate(item))
            else:
                predicate, problems = build_selection(item, get_values, has_field)
                unsupported.extend(problems)
                if predicate is not None:
                    parts.append(predicate)
        if not parts:
            return None, unsupported or ["empty selection list"]
        # I problemi su una branch non invalidano le altre: la regola resta
        # eseguibile se almeno una branch è completa? No: sarebbe una detection
        # parziale. Segnaliamo e lasciamo decidere al chiamante.
        return (_or(parts) if not unsupported else None), unsupported

    if isinstance(spec, str):
        return _keyword_predicate(spec), []

    return None, [f"unsupported selection type: {type(spec).__name__}"]


class _ConditionParser:
    """Parser ricorsivo discendente per la `condition` Sigma."""

    def __init__(self, tokens: List[str], selection_names: Sequence[str]):
        self.tokens = tokens
        self.pos = 0
        self.names = list(selection_names)

    def parse(self) -> Callable[[Dict[str, bool]], bool]:
        expr = self._or_expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.pos]!r}")
        return expr

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _or_expr(self) -> Callable[[Dict[str, bool]], bool]:
        left = self._and_expr()
        while (self._peek() or "").lower() == "or":
            self._take()
            right = self._and_expr()
            left = (lambda a, b: lambda s: a(s) or b(s))(left, right)
        return left

    def _and_expr(self) -> Callable[[Dict[str, bool]], bool]:
        left = self._not_expr()
        while (self._peek() or "").lower() == "and":
            self._take()
            right = self._not_expr()
            left = (lambda a, b: lambda s: a(s) and b(s))(left, right)
        return left

    def _not_expr(self) -> Callable[[Dict[str, bool]], bool]:
        if (self._peek() or "").lower() == "not":
            self._take()
            inner = self._not_expr()
            return lambda s: not inner(s)
        return self._primary()

    def _primary(self) -> Callable[[Dict[str, bool]], bool]:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of condition")
        if token == "(":
            self._take()
            inner = self._or_expr()
            if self._peek() != ")":
                raise ValueError("missing closing parenthesis")
            self._take()
            return inner

        # Quantificatore: `<n> of <set>` oppure `all of <set>`
        low = token.lower()
        is_quant = low in ("all", "any", "none", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10")
        nxt = self.tokens[self.pos + 1] if self.pos + 1 < len(self.tokens) else None
        if is_quant and (nxt or "").lower() == "of":
            count = self._take()
            self._take()  # 'of'
            target = self._take()
            names = self._resolve_set(target)
            if not names:
                raise ValueError(f"condition references unknown selection set {target!r}")
            if count.lower() == "all":
                return lambda s, ns=names: all(s.get(n, False) for n in ns)
            if count.lower() == "any":
                return lambda s, ns=names: any(s.get(n, False) for n in ns)
            if count.lower() == "none":
                return lambda s, ns=names: not any(s.get(n, False) for n in ns)
            needed = int(count)
            return lambda s, ns=names, k=needed: sum(1 for n in ns if s.get(n, False)) >= k

        self._take()
        if token not in self.names:
            raise ValueError(f"condition references unknown selection {token!r}")
        return lambda s, n=token: bool(s.get(n, False))

    def _resolve_set(self, target: str) -> List[str]:
        if target.lower() == "them":
            return list(self.names)
        regex = re.compile(_wildcard_to_regex(target) + "$", re.IGNORECASE)
        return [n for n in self.names if regex.match(n)]


def compile_condition(condition_text: str,
                      selection_names: Sequence[str]) -> Callable[[Dict[str, bool]], bool]:
    """Compila la condizione. Solleva ValueError se non è compilabile."""
    tokens = _TOKEN.findall(condition_text or "")
    if not tokens:
        raise ValueError("empty condition")
    return _ConditionParser(tokens, selection_names).parse()


def compile_detection(
    detection: Dict[str, Any],
    get_values: Callable[[Any, str], List[Any]],
    has_field: Callable[[Any, str], bool],
) -> Tuple[Dict[str, Callable[[Any], bool]], Optional[Callable[[Dict[str, bool]], bool]], List[str]]:
    """Compila l'intero blocco `detection`."""
    if not isinstance(detection, dict):
        return {}, None, ["detection block missing"]
    condition_text = detection.get("condition")
    selections: Dict[str, Callable[[Any], bool]] = {}
    unsupported: List[str] = []
    for name, spec in detection.items():
        if name == "condition":
            continue
        predicate, problems = build_selection(spec, get_values, has_field)
        unsupported.extend(f"{name}: {p}" for p in problems)
        if predicate is not None:
            selections[name] = predicate
    if isinstance(condition_text, list):
        # Condizioni multiple = OR tra condizioni.
        condition_text = " or ".join(f"({c})" for c in condition_text)
    if not condition_text or not isinstance(condition_text, str):
        return selections, None, unsupported + ["missing condition"]
    try:
        condition = compile_condition(condition_text, list(selections.keys()))
    except ValueError as exc:
        return selections, None, unsupported + [f"condition: {exc}"]
    return selections, condition, unsupported
