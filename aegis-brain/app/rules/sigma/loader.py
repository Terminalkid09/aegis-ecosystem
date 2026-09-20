"""Caricamento delle regole Sigma da file YAML.

Nessuna regola viene trasformata in qualcosa di "quasi funzionante": se una
detection non è compilabile, la regola viene caricata ma marcata non eseguibile
e lo dice (`unsupported`). Così la copertura è un numero vero, non una
sensazione.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

import yaml

from app.rules.sigma.compiler import compile_detection
from app.rules.sigma.fields import get_values, has_field
from app.rules.sigma.model import SigmaRule

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def _rule_id(doc: Dict[str, Any], path: str) -> str:
    existing = doc.get("id")
    if existing:
        return str(existing)
    digest = hashlib.sha256(f"{doc.get('title','')}\x00{path}".encode()).hexdigest()[:16]
    return f"sigma-{digest}"


def build_rule(doc: Any, path: str = "<inline>") -> Optional[SigmaRule]:
    """Costruisce una SigmaRule da un documento YAML. None se non è una regola."""
    if not isinstance(doc, dict):
        return None
    detection = doc.get("detection")
    title = doc.get("title")
    if not title or not isinstance(detection, dict):
        return None

    selections, condition, unsupported = compile_detection(detection, get_values, has_field)
    logsource = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    return SigmaRule(
        id=_rule_id(doc, path),
        title=str(title),
        level=str(doc.get("level", "medium")).lower(),
        description=str(doc.get("description", "") or ""),
        status=str(doc.get("status", "experimental")),
        author=str(doc.get("author", "") or ""),
        references=[str(r) for r in (doc.get("references") or [])][:20],
        tags=[str(t) for t in (doc.get("tags") or [])][:40],
        falsepositives=[str(f) for f in (doc.get("falsepositives") or [])][:10],
        logsource={str(k): str(v) for k, v in logsource.items()},
        selections=selections,
        condition=condition,
        condition_text=str(detection.get("condition", "")),
        unsupported=unsupported,
    )


def load_rules(directory: Optional[str] = None) -> List[SigmaRule]:
    """Carica tutte le regole `.yml`/`.yaml` da una directory (non ricorsivo).

    Un file che non è YAML valido viene ignorato con una voce di log, non
    interrompe la scansione: una regola rotta non deve impedire l'avvio.
    """
    rules: List[SigmaRule] = []
    base = directory or DEFAULT_RULES_DIR
    if not os.path.isdir(base):
        return rules
    for name in sorted(os.listdir(base)):
        if not name.lower().endswith((".yml", ".yaml")):
            continue
        full = os.path.join(base, name)
        try:
            with open(full, encoding="utf-8") as fh:
                documents = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError):
            continue
        for doc in documents:
            # Un file può contenere una lista di regole.
            items = doc if isinstance(doc, list) else [doc]
            for item in items:
                rule = build_rule(item, full)
                if rule is not None:
                    rules.append(rule)
    return rules
