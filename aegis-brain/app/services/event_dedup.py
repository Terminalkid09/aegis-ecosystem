"""Dedup idempotente + gap (Fase 4: persistito, bounded, sopravvive a reboot).

- In memoria LRU 20k per latenza microsecondi + Redis SETNX con TTL per
  persistenza cross-reboot e cross-worker. Redis assente → fallback memoria
  (nessuna perdita, solo possibili duplicati su retry a cavallo reboot).
- SeqTracker resta in memoria (gap misurati, mai usati per scartare eventi).
"""
from collections import OrderedDict
import threading
import os


class EventDedup:
    """Finestra LRU di event_id visti per agente. True = duplicato da scartare."""

    def __init__(self, capacity: int = 20000):
        self._capacity = capacity
        self._seen: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.accepted = 0
        self.duplicates = 0

    def check(self, agent_id, event_id) -> bool:
        if not event_id:
            return False  # agenti v1 senza event_id: nessun giudizio
        key = (str(agent_id), str(event_id))
        with self._lock:
            if key in self._seen:
                self.duplicates += 1
                self._seen.move_to_end(key)
                return True
            self._seen[key] = True
            self.accepted += 1
            while len(self._seen) > self._capacity:
                self._seen.popitem(last=False)
            return False

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "accepted": self.accepted,
                "duplicates": self.duplicates,
                "window": len(self._seen),
            }


class SeqTracker:
    """Ultima seq per (agent, boot): conta gap (perdite), reset (reboot con
    boot_id nuovo) e seq duplicate/arretrate (ritrasmissioni)."""

    def __init__(self):
        self._last: dict = {}
        self._boots: dict = {}
        self._lock = threading.Lock()
        self.gaps = 0
        self.gap_events = 0
        self.resets = 0
        self.late = 0
        self.tracked = 0

    def observe(self, agent_id, boot_id, seq) -> dict:
        if seq is None:
            return {"tracked": False}
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            return {"tracked": False}
        if seq < 0:
            return {"tracked": False}
        agent = str(agent_id)
        boot = str(boot_id) if boot_id else ""
        key = (agent, boot)
        with self._lock:
            self.tracked += 1
            prev = self._last.get(key)
            if prev is None:
                known = self._boots.setdefault(agent, set())
                reset = bool(boot and known and boot not in known)
                if boot:
                    known.add(boot)
                if reset:
                    self.resets += 1
                self._last[key] = seq
                return {"tracked": True, "gap": 0, "reset": reset}
            if boot_id and key[1] != str(prev[1] if isinstance(prev, tuple) else ""):
                pass  # boot_id è nella chiave: cambio boot = chiave nuova
            if seq == prev + 1:
                self._last[key] = seq
                return {"tracked": True, "gap": 0, "reset": False}
            if seq > prev + 1:
                gap = seq - prev - 1
                self.gaps += 1
                self.gap_events += gap
                self._last[key] = seq
                return {"tracked": True, "gap": gap, "reset": False}
            self.late += 1
            return {"tracked": True, "gap": 0, "reset": False, "late": True}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "tracked": self.tracked,
                "gaps": self.gaps,
                "gap_events": self.gap_events,
                "resets": self.resets,
                "late": self.late,
                "streams": len(self._last),
            }


DEDUP = EventDedup()
SEQ = SeqTracker()


def snapshot() -> dict:
    return {"dedup": DEDUP.snapshot(), "seq": SEQ.snapshot()}


# Persistenza bounded in Redis (Fase 4): SETNX con TTL, fail-open verso memoria.
# Usata dagli endpoint async; i test puri usano DEDUP.check direttamente.
async def is_duplicate(agent_id, event_id, ttl: int | None = None) -> bool:
    if not event_id:
        return False
    # 1. Prova Redis (cross-reboot/worker)
    try:
        import redis.asyncio as _redis
        from app.core.config import settings
        # TTL configurabile, default da settings
        _ttl = int(ttl) if ttl is not None else int(getattr(settings, "DEDUP_TTL_SECONDS", 86400))
        # Costruisce URL da env se non già impostato (fallback localhost per test)
        url = os.getenv("REDIS_URL") or getattr(settings, "REDIS_URL", "redis://localhost:6379")
        client = _redis.from_url(url, decode_responses=True)
        key = f"dedup:{agent_id}:{event_id}"
        # SETNX con TTL: True = nuovo, False = duplicato
        ok = await client.set(key, "1", ex=_ttl, nx=True)
        await client.aclose()
        if ok is False:  # chiave già presente → duplicato
            DEDUP.duplicates += 1
            return True
        if ok is True:
            # Aggiorna anche la LRU in memoria per letture veloci sincrone
            DEDUP.check(agent_id, event_id)
            return False
    except Exception:
        pass
    # 2. Fallback memoria (test o Redis down)
    return DEDUP.check(agent_id, event_id)
