"""Protezione anti log flood (Fase 1, audit: Redis-first).

Sliding window condivisa su Redis (atomica via Lua: funziona con N worker e
sopravvive al restart); se Redis non risponde, fallback in memoria per-worker
(disponibilita' prima di tutto: l'ingestion non deve mai bloccarsi per il
rate limiter) con eviction delle finestre scadute.

Ceiling via APP_EVENTS_PER_MIN (default 10000 eventi/min). Oltre il budget:
429 con drop_reason=rate_limited — misurato, mai silenzioso.
"""
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_RATE_LUA = """
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
"""


def _redis_client():
    try:
        import redis.asyncio as _redis
    except Exception:
        return None
    try:
        from app.core.redis_utils import get_redis_url
        # Audit: timeout brevi (il default None appende il thread per sempre
        # se l'host droppa i pacchetti invece di rifiutare).
        return _redis.from_url(get_redis_url(), decode_responses=True,
                               socket_connect_timeout=2, socket_timeout=2)
    except Exception:
        return None


# Cooldown globale: se Redis e' giu', non riprovarlo a ogni evento.
_REDIS_DOWN_UNTIL = 0.0
_REDIS_DOWN_COOLDOWN_S = 60.0


class RateGuard:
    def __init__(self, events_per_min: int | None = None, use_redis: bool = True):
        self.events_per_min = events_per_min or getattr(settings, "APP_EVENTS_PER_MIN", 10000)
        self.use_redis = use_redis
        self._windows: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
        self._lock = threading.Lock()
        self.allowlist: set[str] = set()
        self._client = None
        self._redis_warned = False

    def _redis_allow(self, key: str, count: int) -> bool | None:
        """True/False da Redis, None se Redis non disponibile (fallback locale)."""
        global _REDIS_DOWN_UNTIL
        try:
            import asyncio as _asyncio
            import time as _time
            if _time.monotonic() < _REDIS_DOWN_UNTIL:
                return None
            if self._client is None:
                self._client = _redis_client()
            if self._client is None:
                return None
            coro = self._client.eval(_RATE_LUA, 1, key, 60)
            try:
                loop = _asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                # Chiamato da contesto async: non possiamo bloccare; il chiamante
                # async dovrebbe usare allow_async. Fallback locale per ora.
                return None
            current = _asyncio.get_event_loop().run_until_complete(coro)
            # count>1: incrementi extra oltre il primo della Lua
            for _ in range(max(0, count - 1)):
                current = _asyncio.get_event_loop().run_until_complete(
                    self._client.incr(key))
            return int(current) <= self.events_per_min
        except Exception as e:
            _REDIS_DOWN_UNTIL = _time.monotonic() + _REDIS_DOWN_COOLDOWN_S
            if not self._redis_warned:
                logger.warning("RateGuard redis unavailable, local fallback: %s", e)
                self._redis_warned = True
            try:
                if self._client is not None:
                    _asyncio.get_event_loop().run_until_complete(self._client.close())
            except Exception:
                pass
            self._client = None
            return None

    async def allow_async(self, agent_id: str, count: int = 1) -> bool:
        """Variante async: Redis-first (per gli endpoint async)."""
        global _REDIS_DOWN_UNTIL
        if agent_id in self.allowlist:
            return True
        import time as _time2
        if self.use_redis and self._client is None and _time2.monotonic() >= _REDIS_DOWN_UNTIL:
            self._client = _redis_client()
        if self.use_redis and self._client is not None:
            try:
                current = await self._client.eval(_RATE_LUA, 1, f"rg:ingest:{agent_id}", 60)
                for _ in range(max(0, count - 1)):
                    current = await self._client.incr(f"rg:ingest:{agent_id}")
                return int(current) <= self.events_per_min
            except Exception as e:
                _REDIS_DOWN_UNTIL = _time2.monotonic() + _REDIS_DOWN_COOLDOWN_S
                if not self._redis_warned:
                    logger.warning("RateGuard redis unavailable, local fallback: %s", e)
                    self._redis_warned = True
                self._client = None
        return self._local_allow(agent_id, count)

    def allow(self, agent_id: str, count: int = 1) -> bool:
        if agent_id in self.allowlist:
            return True
        if self.use_redis:
            decided = self._redis_allow(f"rg:ingest:{agent_id}", count)
            if decided is not None:
                return decided
        return self._local_allow(agent_id, count)

    def _local_allow(self, agent_id: str, count: int = 1) -> bool:
        now = time.monotonic()
        with self._lock:
            # Eviction finestre scadute (niente crescita illimitata).
            for key, (_c, start) in list(self._windows.items()):
                if now - start >= 120.0:
                    del self._windows[key]
            cur, win_start = self._windows[agent_id]
            if now - win_start >= 60.0:
                cur, win_start = 0, now
            cur += count
            self._windows[agent_id] = (cur, win_start)
            return cur <= self.events_per_min

    def remaining(self, agent_id: str) -> int:
        # Audit: con Redis legge il contatore condiviso (prima leggeva solo
        # il dict locale: con Redis su riportava sempre il budget pieno).
        if self.use_redis:
            try:
                import asyncio as _asyncio
                try:
                    _asyncio.get_running_loop()
                except RuntimeError:
                    if self._client is None:
                        self._client = _redis_client()
                    if self._client is not None:
                        val = _asyncio.get_event_loop().run_until_complete(
                            self._client.get(f"rg:ingest:{agent_id}"))
                        return max(0, self.events_per_min - int(val or 0))
            except Exception:
                pass
        with self._lock:
            cur, win_start = self._windows[agent_id]
            if time.monotonic() - win_start >= 60.0:
                return self.events_per_min
            return max(0, self.events_per_min - cur)

ingest_rate_guard = RateGuard()