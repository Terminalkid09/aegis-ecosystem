"""Bus in-process per gli alert nuovi: push istantaneo ai WebSocket aperti.

Perche' esiste
--------------
Il WS /overview inviava solo lo snapshot dei contatori ogni 30s: un alert
CRITICAL compariva in dashboard al massimo mezzo minuto dopo, e nessuna
notifica browser finche' la React Query non rifreshava la lista. Con il bus
l'alert e' pushed appena creato (stesso processo, nessuna coda esterna).

Vincoli dichiarati:
- single-process: un uvicorn con piu' worker non condividerebbe le queue
  (l'installazione reference gira con 1 worker, scritto nel compose);
- fire-and-forget: publish non blocca mai l'ingest; una queue piena salta
  l'evento per quel client (la dashboard comunque rifresha i dati via REST).
"""
import asyncio
from typing import Any, Dict, Set

_subscribers: Set[asyncio.Queue] = set()


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def publish(payload: Dict[str, Any]) -> None:
    """Pubblica un evento 'alert' a tutti i client. Mai solleva."""
    if not _subscribers:
        return
    event = {"type": "alert", **payload}
    for q in list(_subscribers):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass
