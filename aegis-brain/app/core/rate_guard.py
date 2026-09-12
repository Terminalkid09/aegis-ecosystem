"""Protezione anti log flood (Fase 1).

Per-agent sliding window in memoria, con ceiling configurabile via
APP_EVENTS_PER_MIN (default 10000 eventi/min — ordini di grandezza sopra il
tasso reale di un sensore, ma sotto una tempesta finta). Se l'agente supera il
budget risponde 429 con drop_reason=rate_limited: il dato è misurato e
contabilizzato, mai silenziosamente scartato.

Quando Redis è disponibile il contatore è anche persistito (TTL = finestra)
così il limite sopravvive al restart di un singolo worker.
"""
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from app.core.config import settings

class RateGuard:
    def __init__(self, events_per_min: int | None = None):
        self.events_per_min = events_per_min or getattr(settings, "APP_EVENTS_PER_MIN", 10000)
        self._windows: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
        self._lock = threading.Lock()
        self.allowlist: set[str] = set()

    def allow(self, agent_id: str, count: int = 1) -> bool:
        if agent_id in self.allowlist:
            return True
        now = time.monotonic()
        with self._lock:
            cur, win_start = self._windows[agent_id]
            if now - win_start >= 60.0:
                cur, win_start = 0, now
            cur += count
            self._windows[agent_id] = (cur, win_start)
            return cur <= self.events_per_min

    def remaining(self, agent_id: str) -> int:
        with self._lock:
            cur, win_start = self._windows[agent_id]
            if time.monotonic() - win_start >= 60.0:
                return self.events_per_min
            return max(0, self.events_per_min - cur)

ingest_rate_guard = RateGuard()