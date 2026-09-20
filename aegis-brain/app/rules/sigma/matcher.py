"""Modificatori Sigma e logica di confronto di un campo.

Copre il sottoinsieme di specifica realmente usato dalle regole della
community. I modificatori non supportati **non vengono ignorati**: il
compilatore li restituisce come `unsupported` e la regola viene esclusa, perché
una regola eseguita a metà è peggio di una regola non eseguita.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# Modificatori implementati. `utf16*` sono no-op consapevoli: i valori sono già
# decodificati a stringa dai parser, quindi la variante UTF-16 è soddisfatta.
SUPPORTED_MODIFIERS = frozenset({
    "contains", "startswith", "endswith", "re", "all", "any", "cased",
    "cidr", "gt", "gte", "lt", "lte", "exists", "base64offset", "windash",
    "utf16", "utf16le", "utf16be", "wide", "fieldref",
})
# Modificatori noti in Sigma ma che abbiamo deciso di NON supportare: la regola
# che li usa viene esclusa (e lo dichiara) invece di essere eseguita male.
KNOWN_UNSUPPORTED = frozenset({"expand", "lt", "startswith_expand"}) - {"lt"}

_NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}


def _wildcard_to_regex(pattern: str) -> str:
    """`*` e `?` come wildcard (specifica Sigma).

    Il backslash è letterale (`C:\\Windows` deve restare un percorso Windows):
    in Sigma svolge funzione di escape SOLO davanti a `*`, `?` o a un altro
    backslash. Trattarlo sempre come escape rompeva ogni regola che confronta
    percorsi, che sono la maggioranza delle regole Windows.
    """
    out: List[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def _targets(value: Any) -> List[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _match_text(target: str, pattern: str, mode: str, cased: bool) -> bool:
    """Confronto stringa secondo il modificatore.

    Gli ancoraggi per `contains`/`startswith`/`endswith` vengono aggiunti
    *costruendo la regex*, non concatenando `*` alla stringa: concatenare
    trasformava un backslash finale (es. `\\Temp\\`) in un escape del wildcard
    aggiunto, rompendo ogni regola su percorsi Windows.
    """
    flags = 0 if cased else re.IGNORECASE
    if mode == "re":
        try:
            return re.search(pattern, target, flags | re.DOTALL) is not None
        except re.error:
            return False
    body = _wildcard_to_regex(pattern)
    if mode == "contains":
        regex = f".*{body}.*"
    elif mode == "startswith":
        regex = f"{body}.*"
    elif mode == "endswith":
        regex = f".*{body}"
    else:
        regex = f"{body}"
    try:
        return re.compile(regex, flags | re.DOTALL).fullmatch(target) is not None
    except re.error:
        return False


def _base64_variants(value: str) -> List[str]:
    """Le 3 encoding base64 possibili di un valore (offset 0/1/2)."""
    raw = value.encode("utf-8", "ignore")
    out: List[str] = []
    for offset in range(3):
        padded = b"\x00" * offset + raw
        encoded = base64.b64encode(padded).decode("ascii")
        strip = {0: 0, 1: 2, 2: 3}[offset]
        out.append(encoded[strip:].rstrip("="))
    return [v for v in out if v]


def _windash_variants(value: str) -> List[str]:
    """Sigma `windash`: `-flag` può comparire come `/flag` o con en/em dash."""
    return [value, value.replace("-", "/"), value.replace("-", "\u2013"),
            value.replace("-", "\u2014")]


def _cidr_match(target: str, pattern: str) -> bool:
    try:
        return ipaddress.ip_address(target.strip()) in ipaddress.ip_network(str(pattern), strict=False)
    except ValueError:
        return False


def _numeric_compare(target: Any, pattern: Any, modifier: str) -> bool:
    try:
        left, right = float(target), float(pattern)
    except (TypeError, ValueError):
        return False
    return {"gt": left > right, "gte": left >= right,
            "lt": left < right, "lte": left <= right}[modifier]


def compile_field_match(
    field: str,
    modifiers: Sequence[str],
    patterns: Any,
    get_values: Callable[[Any, str], List[Any]],
    has_field: Callable[[Any, str], bool],
) -> Tuple[Optional[Callable[[Any], bool]], List[str]]:
    """Compila un test di campo. Ritorna (predicato | None, modificatori non supportati)."""
    mods = [m.lower() for m in modifiers]
    unknown = [m for m in mods if m not in SUPPORTED_MODIFIERS]
    if unknown:
        return None, [f"unsupported modifier(s): {', '.join(sorted(set(unknown)))}"]
    if "fieldref" in mods:
        return None, ["modifier 'fieldref' not supported"]

    pattern_list = patterns if isinstance(patterns, list) else [patterns]
    require_all = "all" in mods
    cased = "cased" in mods
    exists_mod = "exists" in mods
    b64 = "base64offset" in mods
    windash = "windash" in mods
    numeric = next((m for m in mods if m in _NUMERIC_MODIFIERS), None)
    mode = next((m for m in mods if m in ("contains", "startswith", "endswith", "re")), "equals")
    # `any` è l'esplicitazione del default: nessun cambio di comportamento.

    def predicate(event: Any) -> bool:
        if exists_mod:
            present = has_field(event, field)
            wanted = [str(p).strip().lower() in ("true", "1", "yes") for p in pattern_list]
            return present in wanted
        values = get_values(event, field)
        if not values:
            return False
        results: List[bool] = []
        for pattern in pattern_list:
            matched = False
            for value in values:
                if numeric:
                    if _numeric_compare(value, pattern, numeric):
                        matched = True
                        break
                    continue
                for target in _targets(value):
                    candidates = [pattern]
                    if b64:
                        candidates = _base64_variants(str(pattern))
                    for candidate in candidates:
                        if "cidr" in mods:
                            if _cidr_match(target, str(candidate)):
                                matched = True
                                break
                            continue
                        if windash:
                            if any(_match_text(target, v, mode, cased)
                                   for v in _windash_variants(str(candidate))):
                                matched = True
                                break
                            continue
                        if _match_text(target, str(candidate), mode, cased):
                            matched = True
                            break
                    if matched:
                        break
                if matched:
                    break
            results.append(matched)
        return all(results) if require_all else any(results)

    return predicate, []


def level_to_severity(level: Optional[str]) -> str:
    """Sigma level → severità interna (usata quando la detection crea un alert)."""
    return {"informational": "INFO", "low": "LOW", "medium": "MEDIUM",
            "high": "HIGH", "critical": "CRITICAL"}.get(
        str(level or "").strip().lower(), "MEDIUM")
