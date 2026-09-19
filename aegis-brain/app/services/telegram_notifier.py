"""Notifiche Telegram per alert HIGH/CRITICAL: il guardiano che parla quando
la dashboard e' chiusa.

Perche' esiste
--------------
Prima di questo modulo gli unici canali "notification" erano due toggle
cosmetici in localStorage (nessun codice li leggeva) e il WebSocket, che parla
solo mentre la dashboard e' aperta. Per il regime h24 serve il contrario: il
sistema chiama TE, non aspettare che tu apra la pagina.

Design
------
- Fire-and-forget in-process (asyncio task, nessuna coda esterna): un notify
  fallito non puo' mai rompere l'ingest della telemetria. Tutto loggato, tutto
  fail-soft, con cooldown per non floodare la chat in un'epidemia di alert.
- Config in `app_settings` (bot token cifrato in `integration_settings`,
  chat_id, severita' minima, enable): modificabile dalla UI senza riavvii.
- Il bot token e' un segreto: cifrato con lo stesso KEK di Shodan/VirusTotal,
  mai in chiaro nel DB, mai nei log.
- Cooldown per (severity, event_type) di 10 minuti: 500 tentativi di accesso
  falliti non diventano 500 messaggi.

Testabilita': `_send()` e' l'unico punto I/O, iniettato: i test passano un
fake e verificano Che cosa SAREBBE stato inviato, senza rete.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.database.models import Agent
from app.services import integration_settings, app_settings

logger = logging.getLogger("aegis.telegram")

# Cooldown per (severity, event_type): una raffica di alert uguali non deve
# trasformarsi in raffica di messaggi (Telegram limitera' comunque a ~1 msg/s).
_COOLDOWN_SECONDS = 600
_last_sent: Dict[str, float] = {}

_enabled: Optional[bool] = None
_cache_loaded = False


def invalidate_cache() -> None:
    """La UI ha cambiato la config: la cache delle impostazioni muore."""
    global _enabled, _cache_loaded
    _enabled = None
    _cache_loaded = False
    _last_sent.clear()


async def _ensure_cache(db: AsyncSession) -> None:
    """Carica la config telegram una volta (o dopo invalidazione UI)."""
    global _cache_loaded
    if not _cache_loaded:
        await app_settings.refresh_telegram_cache(db)
        _cache_loaded = True


def _min_severity() -> str:
    return (app_settings.get_cached("telegram.min_severity") or "HIGH").upper()


def _is_enabled() -> bool:
    global _enabled
    if _enabled is None:
        _enabled = (app_settings.get_cached("telegram.enabled") or "").lower() == "true"
    return _enabled


def _format_message(alert: Dict[str, Any], hostname: Optional[str]) -> str:
    """Messaggio compatto, leggibile su telefono, senza markdown complesso."""
    sev = (alert.get("severity") or "?").upper()
    emoji = "\U0001F6A8" if sev in ("CRITICAL", "HIGH") else "\u26A0\uFE0F"
    host = hostname or str(alert.get("agent_id", ""))[:8]
    ts = alert.get("timestamp")
    when = ts.strftime("%d/%m %H:%M:%S UTC") if isinstance(ts, datetime) else str(ts or "")
    lines = [
        f"{emoji} Aegis {sev} alert",
        f"Host: {host}",
        f"Event: {alert.get('event_type', '?')}",
        f"Process: {alert.get('process_name', '?')}",
    ]
    if alert.get("mitre_technique_id"):
        lines.append(f"MITRE: {alert['mitre_technique_id']} {alert.get('mitre_technique_name', '')}".rstrip())
    if alert.get("process_path"):
        lines.append(f"Path: {alert['process_path']}")
    desc = (alert.get("description") or "").strip()
    if desc:
        lines.append(f"Detail: {desc[:300]}")
    lines.append(f"At: {when}")
    return "\n".join(lines)


async def notify_alert(db: AsyncSession, alert: Any) -> None:
    """Punto unico di ingresso: chiamato alla creazione di ogni alert.

    Mai sollevare: un problema Telegram non deve mai far fallire l'ingest.
    """
    try:
        await _ensure_cache(db)
        if not _is_enabled():
            return
        sev = (getattr(alert, "severity", "") or "").upper()
        if sev not in ("HIGH", "CRITICAL"):
            return
        min_sev = _min_severity()
        if min_sev == "CRITICAL" and sev != "CRITICAL":
            return

        token = await integration_settings.get_key(db, "telegram_bot_token")
        if not token:
            logger.warning("telegram: enabled but bot token missing; notification skipped")
            return
        chat_id = (app_settings.get_cached("telegram.chat_id") or "").strip()
        if not chat_id:
            logger.warning("telegram: enabled but chat_id missing; notification skipped")
            return

        cooldown_key = f"{sev}:{getattr(alert, 'event_type', '?')}"
        now = time.monotonic()
        if now - _last_sent.get(cooldown_key, 0) < _COOLDOWN_SECONDS:
            return
        _last_sent[cooldown_key] = now

        # Hostname: campo cosmetico del messaggio. La lookup e' incapsulata
        # perche' un fallimento qui NON deve mai sopprimere la notifica (gia'
        # successo: su CI l'errore veniva inghiottito dal fail-soft esterno e
        # l'alert non arrivava mai). La notifica si regge su token+chat+testo.
        agent_id = str(getattr(alert, "agent_id", "") or "")
        hostname: Optional[str] = None
        try:
            if agent_id:
                res = await db.execute(
                    select(Agent.hostname).where(Agent.agent_id == agent_id))
                hostname = res.scalar_one_or_none()
        except Exception:  # noqa: BLE001 — hostname mancante < alert perso
            logger.debug("telegram: hostname lookup failed for %s", agent_id[:8])
        text = _format_message(_alert_dict(alert), hostname)
        await _send(token, chat_id, text)
        logger.info("telegram: notified %s alert on %s", sev, hostname or agent_id[:8])
    except Exception:  # noqa: BLE001 — fail-soft per contratto
        logger.exception("telegram: notification failed (alert ingest unaffected)")


def _alert_dict(alert: Any) -> Dict[str, Any]:
    return {
        "severity": getattr(alert, "severity", None),
        "event_type": getattr(alert, "event_type", None),
        "process_name": getattr(alert, "process_name", None),
        "process_path": getattr(alert, "process_path", None),
        "description": getattr(alert, "description", None),
        "timestamp": getattr(alert, "timestamp", None),
        "agent_id": str(getattr(alert, "agent_id", "") or ""),
        "mitre_technique_id": getattr(alert, "mitre_technique_id", None),
        "mitre_technique_name": getattr(alert, "mitre_technique_name", None),
    }


async def _send(token: str, chat_id: str, text: str) -> None:
    """Chiamata HTTP reale a Bot API (isolata per i test)."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
        )
        if resp.status_code != 200:
            logger.error("telegram: sendMessage failed %s: %s", resp.status_code, resp.text[:200])


async def send_test_message(db: AsyncSession) -> Dict[str, Any]:
    """Bottone 'Send test' dalla UI: verifica credenziali senza aspettare un alert."""
    token = await integration_settings.get_key(db, "telegram_bot_token")
    chat_id = (app_settings.get_cached("telegram.chat_id") or "").strip()
    if not token or not chat_id:
        return {"ok": False, "error": "bot token or chat_id missing"}
    try:
        await _ensure_cache(db)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": "\u2705 Aegis test message: notifications are working."},
            )
        if resp.status_code == 200:
            return {"ok": True}
        return {"ok": False, "error": f"telegram answered {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200]}


# ---------------------------------------------------------------------------
# Heartbeat periodico: "Aegis e' vivo"
# ---------------------------------------------------------------------------

_task: Optional[asyncio.Task] = None


async def _heartbeat_loop() -> None:
    while True:
        db = None
        try:
            await asyncio.sleep(_heartbeat_interval())
            db = _session_factory()
            await _ensure_cache(db)
            if not _is_enabled():
                continue
            token = await integration_settings.get_key(db, "telegram_bot_token")
            chat_id = (app_settings.get_cached("telegram.chat_id") or "").strip()
            if token and chat_id:
                await _send(token, chat_id, "\U0001F41D Aegis heartbeat: platform is up and watching.")
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001
            logger.exception("telegram: heartbeat loop error")
        finally:
            if db is not None:
                try:
                    await _db_cleanup(db)
                except Exception:  # noqa: BLE001
                    logger.exception("telegram: heartbeat db cleanup failed")


def _heartbeat_interval() -> int:
    raw = (app_settings.get_cached("telegram.heartbeat_minutes") or "60").strip()
    try:
        return max(15, int(raw)) * 60
    except ValueError:
        return 3600


def start_heartbeat(session_factory, db_cleanup) -> None:
    """Avvia il task heartbeat (chiamato dal lifespan)."""
    global _task, _session_factory, _db_cleanup
    _session_factory = session_factory
    _db_cleanup = db_cleanup
    if _task is None or _task.done():
        _task = asyncio.create_task(_heartbeat_loop())


async def stop_heartbeat() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None


_session_factory = None
_db_cleanup = None
