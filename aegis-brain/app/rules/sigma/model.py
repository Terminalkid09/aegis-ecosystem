"""Modello di una regola Sigma caricata (con tracciamento dell'unsupported)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class FieldMatch:
    """Un test `campo[|modificatori]: valore(i)` dentro una selection."""

    field: str
    modifiers: List[str]
    patterns: List[Any]

    def describe(self) -> str:
        mods = "".join(f"|{m}" for m in self.modifiers)
        return f"{self.field}{mods}"


@dataclass
class SigmaRule:
    """Regola Sigma pronta all'esecuzione."""

    id: str
    title: str
    level: str = "medium"
    description: str = ""
    status: str = "experimental"
    author: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    logsource: Dict[str, Any] = field(default_factory=dict)
    # selections: nome → funzione(event) → bool
    selections: Dict[str, Callable[[Any], bool]] = field(default_factory=dict)
    # condition già compilata: funzione(dict[nome→bool]) → bool
    condition: Optional[Callable[[Dict[str, bool]], bool]] = None
    condition_text: str = ""
    unsupported: List[str] = field(default_factory=list)

    @property
    def executable(self) -> bool:
        return not self.unsupported and self.condition is not None

    def mitre_techniques(self) -> List[str]:
        out = []
        for tag in self.tags:
            low = str(tag).lower()
            if low.startswith("attack.t"):
                out.append(low.split(".", 1)[1].upper())
        return out

    def to_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "level": self.level,
            "status": self.status,
            "description": self.description,
            "logsource": self.logsource,
            "selections": sorted(self.selections.keys()),
            "condition": self.condition_text,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques(),
            "falsepositives": self.falsepositives,
            "executable": self.executable,
            "unsupported": self.unsupported,
        }


@dataclass
class SigmaMatch:
    """Una regola che ha fatto match su un evento."""

    rule_id: str
    title: str
    level: str
    description: str
    mitre_techniques: List[str]
    tags: List[str]
    event_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "event_id": self.event_id,
            "engine": "sigma",
        }
