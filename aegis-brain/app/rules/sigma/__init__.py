"""Motore regole Sigma.

Sigma è lo standard de-facto di detection content: regole YAML scritte dalla
community (migliaia), pensate per essere portabili tra SIEM. Eseguirle
direttamente significa non chiedere al cliente di riscrivere la propria
detection: si importa un ecosistema invece di un file.

Supportiamo consapevolmente un sottoinsieme e **dichiariamo** ciò che non
supportiamo (vedi `SigmaRule.unsupported`): una regola che non possiamo
eseguire correttamente viene esclusa e contata, mai eseguita a metà.
"""
from app.rules.sigma.engine import SigmaEngine, get_engine
from app.rules.sigma.loader import load_rules
from app.rules.sigma.model import SigmaMatch, SigmaRule

__all__ = ["SigmaEngine", "get_engine", "load_rules", "SigmaMatch", "SigmaRule"]
