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

from app.database.models import Agent
from app.services import integration_settings, app_settings

logger = logging.getLogger("aegis.telegram")

# Cooldown per (severity, event_type): una raffica di alert uguali non deve
# trasformarsi in raffica di messaggi (Telegram limitera' comunque a ~1 msg/s).
_COOLDOWN_SECONDS = 600
_last_sent: Dict[str, float] = {}

# Scala di severita' degli alert: la soglia minima configurabile (`telegram.
# min_severity`) filtra "sotto questo livello non chiamare". Prima la porta
# era cablata a HIGH/CRITICAL e nessuna impostazione poteva aprirla: ora la
# scelta e' dell'operatore, il default resta HIGH (zero rumore nuovo).
SEVERITY_RANK: Dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}
DEFAULT_MIN_SEVERITY = "HIGH"
VALID_MIN_SEVERITIES = tuple(SEVERITY_RANK)

_enabled: Optional[bool] = None
_cache_loaded = False


def invalidate_cache() -> None:
    """La UI ha cambiato la config: la cache delle impostazioni muore.

    Deve morire ANCHE la cache di `app_settings`: azzerare solo i flag di
    questo modulo non bastava, perché la lettura successiva poteva ancora
    vedere il valore VECCHIO. Sintomo reale riportato dall'operatore: si
    salvava il chat_id appena copiato e "Send test" rispondeva ancora
    "chat_id missing" — il valore c'era, la cache no. Un timer che scade
    "prima o poi" non e' una risposta accettabile per un pulsante che
    l'utente ha appena premuto.
    """
    global _enabled, _cache_loaded
    _enabled = None
    _cache_loaded = False
    _last_sent.clear()
    app_settings.invalidate_telegram_cache()


async def _ensure_cache(db: AsyncSession) -> None:
    """Carica la config telegram una volta (o dopo invalidazione UI)."""
    global _cache_loaded
    if not _cache_loaded:
        await app_settings.refresh_telegram_cache(db)
        _cache_loaded = True


def _min_severity() -> str:
    return (app_settings.get_cached("telegram.min_severity")
            or DEFAULT_MIN_SEVERITY).upper()


def _is_enabled() -> bool:
    global _enabled
    if _enabled is None:
        _enabled = (app_settings.get_cached("telegram.enabled") or "").lower() == "true"
    return _enabled


SEVERITY_EMOJI = {
    "CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
    "LOW": "\U0001F535", "INFO": "\u26AA",
}


def _esc(value: Any) -> str:
    """Escape per parse_mode=HTML di Telegram.

    Perche' e' obbligatorio: nomi di processo, path e command line sono dati
    dell'endpoint e possono contenere `<`, `>` o `&`. Con parse_mode=HTML un
    carattere non escapato fa rispondere 400 al Bot API e il messaggio NON
    parte: un alert perso per una formattazione. Qui si neutralizza il testo,
    e `_send` ha comunque un fallback senza formattazione.
    """
    text = str(value if value is not None else "")
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def _format_message(alert: Dict[str, Any], hostname: Optional[str]) -> str:
    """Messaggio separato in blocchi, leggibile sul telefono.

    Prima era un blocco unico di righe appiccicate: host, evento, processo e
    dettaglio si leggevano come un paragrafo solo. Ora c'e' un'intestazione
    con severita' e host, le righe chiave etichettate, il comando in
    monospazio (copiabile) e un piè di pagina con orario e id alert.
    """
    sev = (alert.get("severity") or "?").upper()
    emoji = SEVERITY_EMOJI.get(sev, "\u26AA")
    host = hostname or str(alert.get("agent_id", ""))[:8]
    ts = alert.get("timestamp")
    when = ts.strftime("%d/%m %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")

    # Il marchio in testa non e' decorazione: su un telefono con piu' bot
    # attivi e' cio' che dice a colpo d'occhio da dove arriva il messaggio.
    head = f"\U0001F6E1 <b>Aegis</b> \u00b7 {emoji} <b>{_esc(sev)}</b> \u00b7 <b>{_esc(host)}</b>"
    rows = [
        ("Event", _esc(alert.get("event_type") or "?")),
        ("Process", _esc(alert.get("process_name") or "?")),
    ]
    if alert.get("pid"):
        rows.append(("PID", f"<code>{_esc(alert['pid'])}</code>"))
    if alert.get("parent_process_name"):
        rows.append(("Parent", _esc(alert["parent_process_name"])))
    if alert.get("mitre_technique_id"):
        tech = f"{alert['mitre_technique_id']} {alert.get('mitre_technique_name') or ''}".strip()
        rows.append(("MITRE", _esc(tech)))
    if alert.get("process_path"):
        rows.append(("Path", f"<code>{_esc(alert['process_path'])}</code>"))

    blocks = [head, "\u2500" * 18]
    blocks.append("\n".join(f"<b>{k}</b>  {v}" for k, v in rows))

    # Command line e dettaglio: blocco a parte, cosi' non si mescolano alle
    # righe etichettate e restano copiabili senza selezionare il resto.
    cmd = (alert.get("command_line") or "").strip()
    if cmd:
        blocks.append("<b>Command</b>\n<code>" + _esc(cmd[:400]) + "</code>")
    desc = (alert.get("description") or "").strip()
    if desc:
        blocks.append("<b>Detail</b>\n" + _esc(desc[:400]))

    footer = f"\U0001F552 {_esc(when)} UTC"
    if alert.get("id"):
        footer += f" \u00b7 alert #{_esc(alert['id'])}"
    blocks.append("\u2500" * 18)
    blocks.append(footer)
    return "\n".join(blocks)


def _format_resolved(alert: Dict[str, Any], hostname: Optional[str],
                     reopened: bool = False) -> str:
    """Notifica di chiusura (o riapertura) di un alert.

    Stessa soglia di severita' delle notifiche di apertura: chi ha scelto
    "solo CRITICAL" non vuole il traffico delle chiusure minori. Il risk
    level dell'alert e' l'unico criterio, come richiesto.
    """
    sev = (alert.get("severity") or "?").upper()
    host = hostname or str(alert.get("agent_id", ""))[:8]
    icon = "\U0001F504" if reopened else "\u2705"
    verb = "REOPENED" if reopened else "RESOLVED"
    rows = [
        ("Event", _esc(alert.get("event_type") or "?")),
        ("Process", _esc(alert.get("process_name") or "?")),
    ]
    if alert.get("mitre_technique_id"):
        tech = f"{alert['mitre_technique_id']} {alert.get('mitre_technique_name') or ''}".strip()
        rows.append(("MITRE", _esc(tech)))
    body = "\n".join(f"<b>{k}</b>  {v}" for k, v in rows)
    head = f"{icon} <b>{verb}</b> \u00b7 {_esc(SEVERITY_EMOJI.get(sev, ''))} {_esc(sev)} \u00b7 <b>{_esc(host)}</b>"
    out = [head, "\u2500" * 18, body]
    if alert.get("id"):
        out.append(f"<b>Alert</b>  #{_esc(alert['id'])}")
    return "\n".join(out)


async def notify_alert(db: AsyncSession, alert: Any) -> None:
    """Punto unico di ingresso: chiamato alla creazione di ogni alert.

    Mai sollevare: un problema Telegram non deve mai far fallire l'ingest.
    """
    try:
        await _ensure_cache(db)
        if not _is_enabled():
            return
        sev = (getattr(alert, "severity", "") or "").upper()
        if not _severity_allows(sev):
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
        # `None` = mai inviato: deve partire SUBITO. Il default 0 era un bug
        # reale (su CI l'uptime del runner e' < cooldown, quindi il primo
        # alert di sempre veniva silenziato come "in cooldown" — e nessun log,
        # perche' e' un return silenzioso, non un'eccezione).
        last = _last_sent.get(cooldown_key)
        if last is not None and now - last < _COOLDOWN_SECONDS:
            return
        _last_sent[cooldown_key] = now

        # Hostname: campo cosmetico del messaggio. La lookup e' incapsulata
        # perche' un fallimento qui NON deve mai sopprimere la notifica (gia'
        # successo: su CI l'errore veniva inghiottito dal fail-soft esterno e
        # l'alert non arrivava mai). La notifica si regge su token+chat+testo.
        agent_id = str(getattr(alert, "agent_id", "") or "")
        hostname = await _hostname_for(db, agent_id)
        text = _format_message(_alert_dict(alert), hostname)
        await _send(token, chat_id, text)
        logger.info("telegram: notified %s alert on %s", sev, hostname or agent_id[:8])
    except Exception:  # noqa: BLE001 — fail-soft per contratto
        logger.exception("telegram: notification failed (alert ingest unaffected)")


# `sup:tg-resolved:<id>` evita il doppio messaggio quando l'operatore risolve
# due volte lo stesso alert (o riapre e richiude): il testo di chiusura si
# invia una volta per transizione.
_RESOLVED_SENT: Dict[str, float] = {}
_RESOLVED_TTL_SECONDS = 3600


async def notify_alert_resolved(db: AsyncSession, alert: Any,
                                reopened: bool = False) -> None:
    """Notifica di chiusura/riapertura di un alert.

    Perche' serve: senza, il telefono dice "qualcosa e' successo" e mai "e'
    finita". Un operatore che gestisce il SOC dal telefono vuole sapere anche
    quando l'alert e' stato chiuso — e solo per le severita' che ha scelto di
    seguire (stessa soglia delle notifiche di apertura).

    Mai sollevare: la triage dell'operatore non deve dipendere da Telegram.
    """
    try:
        await _ensure_cache(db)
        if not _is_enabled():
            return
        sev = (getattr(alert, "severity", "") or "").upper()
        if not _severity_allows(sev):
            return
        token = await integration_settings.get_key(db, "telegram_bot_token")
        chat_id = (app_settings.get_cached("telegram.chat_id") or "").strip()
        if not token or not chat_id:
            return
        key = f"{getattr(alert, 'id', '?')}:{'reopened' if reopened else 'resolved'}"
        now = time.monotonic()
        if key in _RESOLVED_SENT and now - _RESOLVED_SENT[key] < _RESOLVED_TTL_SECONDS:
            return
        _RESOLVED_SENT[key] = now
        if len(_RESOLVED_SENT) > 500:
            _RESOLVED_SENT.clear()
            _RESOLVED_SENT[key] = now
        agent_id = str(getattr(alert, "agent_id", "") or "")
        hostname = await _hostname_for(db, agent_id)
        await _send(token, chat_id, _format_resolved(_alert_dict(alert), hostname, reopened))
        logger.info("telegram: notified %s %s on %s", sev,
                    "reopen" if reopened else "resolve", hostname or agent_id[:8])
    except Exception:  # noqa: BLE001 — fail-soft per contratto
        logger.exception("telegram: resolve notification failed (triage unaffected)")


def _severity_allows(sev: str) -> bool:
    """Unico punto in cui si decide se una severita' merita un messaggio.

    Usato sia per gli alert aperti sia per le chiusure: la soglia e' la stessa
    e questo evita che i due percorsi divergano (chi sceglie CRITICAL non
    riceve ne' HIGH aperti ne' HIGH risolti).
    """
    rank = SEVERITY_RANK.get(sev)
    if rank is None:
        return False  # severita' ignota: non inventiamo, resta in dashboard
    return rank >= SEVERITY_RANK.get(_min_severity(), SEVERITY_RANK[DEFAULT_MIN_SEVERITY])


def _alert_dict(alert: Any) -> Dict[str, Any]:
    return {
        "id": getattr(alert, "id", None),
        "severity": getattr(alert, "severity", None),
        "event_type": getattr(alert, "event_type", None),
        "process_name": getattr(alert, "process_name", None),
        "process_path": getattr(alert, "process_path", None),
        "parent_process_name": getattr(alert, "parent_process_name", None),
        "command_line": getattr(alert, "command_line", None),
        "pid": getattr(alert, "pid", None),
        "description": getattr(alert, "description", None),
        "timestamp": getattr(alert, "timestamp", None),
        "agent_id": str(getattr(alert, "agent_id", "") or ""),
        "mitre_technique_id": getattr(alert, "mitre_technique_id", None),
        "mitre_technique_name": getattr(alert, "mitre_technique_name", None),
    }


async def _hostname_for(db: AsyncSession, agent_id: str) -> Optional[str]:
    """Hostname leggibile: un fallimento NON deve sopprimere la notifica."""
    try:
        if agent_id:
            res = await db.execute(
                select(Agent.hostname).where(Agent.agent_id == agent_id))
            return res.scalar_one_or_none()
    except Exception:  # noqa: BLE001 — hostname mancante < alert perso
        logger.debug("telegram: hostname lookup failed for %s", str(agent_id)[:8])
    return None


async def _send(token: str, chat_id: str, text: str,
                parse_mode: str = "HTML") -> Optional[str]:
    """Chiamata HTTP reale a Bot API (isolata per i test).

    Unico punto di I/O verso Telegram: le notifiche, i comandi e il pulsante
    "Send test" passano tutti da qui. Duplicare la chiamata (come faceva
    `send_test_message`) significava avere due comportamenti diversi per lo
    stesso invio — e il pulsante di verifica non era coperto dai test del
    notifier.

    Ritorna `None` se il messaggio e' partito, altrimenti il motivo del
    fallimento (per il pulsante "Send test", che deve poterlo mostrare).

    Rete di sicurezza sulla formattazione: se Telegram rifiuta il messaggio
    (400) si rimanda in testo semplice. Un alert deve arrivare anche se una
    nuova decorazione introduce un carattere che il parser rifiuta.
    """
    payload: Dict[str, Any] = {"chat_id": chat_id, "text": text,
                               "disable_web_page_preview": True}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                                 json=payload)
        if resp.status_code != 200:
            logger.error("telegram: sendMessage failed %s: %s",
                         resp.status_code, resp.text[:200])
            if parse_mode and resp.status_code == 400:
                logger.warning("telegram: retry senza formattazione (testo semplice)")
                retry = await client.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat_id, "text": text,
                          "disable_web_page_preview": True})
                if retry.status_code == 200:
                    return None
            return f"telegram answered {resp.status_code}: {resp.text[:200]}"
    return None


async def send_test_message(db: AsyncSession) -> Dict[str, Any]:
    """Bottone 'Send test' dalla UI: verifica credenziali senza aspettare un alert.

    Legge `chat_id` e token DIRETTAMENTE dal database, non dalla cache: il
    pulsante viene premuto subito dopo un salvataggio, e la cache poteva
    ancora contenere il valore precedente (vuoto) → "chat_id missing" su un
    chat_id appena scritto. La verifica di configurazione non deve mai
    dipendere da quanto e' vecchia una cache in-process.
    """
    await _ensure_cache(db)
    token = await integration_settings.get_key(db, "telegram_bot_token")
    chat_id = (await app_settings.get_value(db, "telegram.chat_id") or "").strip()
    # Errore PRECISO, non ambiguo: prima diceva "token or chat_id missing" e
    # l'operatore non sapeva QUALE dei due rimediare (e provava a risalvare
    # il token che invece era corretto).
    if not token:
        return {"ok": False, "error": "bot token missing — save it in Integrations & API Keys (full format: 123456789:ABC...)"}
    if not chat_id:
        return {"ok": False, "error": "chat_id missing — use 'Detect chat ID' below after sending your bot a message"}
    text = ("\u2705 <b>Aegis</b> \u2014 test message\n"
            + "\u2500" * 18 + "\n"
            + "Notifications are working: this is the same format you will "
              "get for alerts, plus <b>/status</b> and <b>/alerts</b> as "
              "remote commands.")
    try:
        error = await _send(token, chat_id, text)
    except Exception as exc:  # noqa: BLE001 — l'errore va MOSTRATO, non inghiottito
        return {"ok": False, "error": str(exc)[:200]}
    if error:
        return {"ok": False, "error": error}
    return {"ok": True}


async def _get_updates(token: str, offset: int = 0,
                       timeout: int = 0) -> httpx.Response:
    """getUpdates del Bot API (isolato per i test, come _send).

    `offset` conferma al Bot API gli update gia' gestiti: senza, il loop dei
    comandi rilavorerebbe sempre lo stesso messaggio. `timeout` > 0 attiva il
    long polling, cosi' il comando ricevuto ha latenza di secondi senza che il
    processo interroghi Telegram a vuoto.
    """
    params: Dict[str, Any] = {}
    if offset:
        params["offset"] = offset
    if timeout:
        params["timeout"] = timeout
    async with httpx.AsyncClient(timeout=timeout + 10) as client:
        return await client.get(f"https://api.telegram.org/bot{token}/getUpdates",
                                params=params)


async def detect_chats(db: AsyncSession) -> Dict[str, Any]:
    """Scopre i chat_id che hanno scritto al bot (bottone 'Detect chat ID').

    Perche' serve: il chat_id personale NON e' il @username del bot e non
    c'e' modo di indovinarlo — il bot lo scopre solo quando l'utente gli
    scrive (getUpdates). Senza questo bottone l'operatore doveva chiamare
    l'API a mano o usare @userinfobot.
    """
    token = await integration_settings.get_key(db, "telegram_bot_token")
    if not token:
        return {"ok": False,
                "error": "bot token missing — save it in Integrations & API Keys"}
    try:
        resp = await _get_updates(token)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200]}
    if resp.status_code != 200:
        return {"ok": False,
                "error": f"telegram answered {resp.status_code}: {resp.text[:200]}"}

    chats: Dict[int, Dict[str, Any]] = dict(_known_chats)
    try:
        for update in resp.json().get("result", []):
            _remember_chat(update)
    except Exception as exc:  # noqa: BLE001 — payload inatteso: mai 500
        return {"ok": False, "error": f"unexpected telegram payload: {exc}"}
    chats.update(_known_chats)

    out = {"ok": True, "chats": sorted(chats.values(), key=lambda c: str(c["id"]))}
    if not out["chats"]:
        out["hint"] = ("No chats found. Open Telegram, send your bot ANY message "
                       "(e.g. /start), then press Detect again.")
    return out


# ---------------------------------------------------------------------------
# Comandi del telecomando: /status, /alerts, /help
# ---------------------------------------------------------------------------
#
# Perche' esistono: Telegram serve a sapere "sta girando? chi e' online?"
# senza aprire la dashboard. Non e' una seconda dashboard: qui si risponde
# con poche righe e si rimanda al SOC per il triage vero.
#
# Sicurezza: i comandi che mostrano dati rispondono SOLO al chat_id
# configurato. /start invece risponde sempre — e' il modo con cui Telegram
# fa scoprire il proprio chat_id a chi scrive al bot (stessa persona, nessun
# dato di sistema), ed e' cio' che rende usabile il passo "Detect chat ID".

_HELP = (
    "\U0001F916 <b>Aegis \u2014 commands</b>\n" + "\u2500" * 18 + "\n"
    "<b>/status</b>   agents, devices and last contact\n"
    "<b>/alerts</b>   open alerts (above your threshold)\n"
    "<b>/help</b>     this message\n"
    + "\u2500" * 18 + "\n"
    "Full triage stays on the dashboard."
)

_known_chats: Dict[int, Dict[str, Any]] = {}


def _remember_chat(update: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Registra la chat vista (per il bottone Detect) e ritorna il messaggio."""
    msg = update.get("message") or update.get("channel_post") or {}
    chat = msg.get("chat") or {}
    cid = chat.get("id")
    if cid is None:
        return None
    _known_chats[cid] = {
        "id": cid,
        "type": chat.get("type", ""),
        "title": chat.get("title") or chat.get("first_name") or "",
        "username": chat.get("username") or "",
    }
    if len(_known_chats) > 50:  # bound: un bot pubblico non deve crescere senza fine
        _known_chats.pop(next(iter(_known_chats)))
    return msg


async def _cmd_status(db: AsyncSession) -> str:
    """Agenti e host: l'unica domanda che si fa dal telefono."""
    # Ordinamento in Python e non in SQL: `nulls_last()` cambia nome fra le
    # versioni di SQLAlchemy e l'ordine dei NULL in DESC cambia fra i dialetti
    # (Postgres li mette per primi). Qui il risultato deve essere "chi ha
    # parlato di recente in alto", uguale su qualunque backend.
    res = await db.execute(select(Agent).limit(200))
    agents = list(res.scalars().all())
    if not agents:
        return "\U0001F4AD No agents registered yet."
    agents.sort(key=lambda a: (getattr(a, "last_seen", None) is None,
                               -(getattr(a, "last_seen", None).timestamp()
                                 if getattr(a, "last_seen", None) else 0)))
    now = datetime.now(timezone.utc)
    rows = []
    online = 0
    # Tetto alle righe: il telefono non e' una tabella. Gli agenti online
    # stanno in cima (ordinati sopra), il resto e' un conteggio — la lista
    # completa, con filtri e ricerca, e' la dashboard.
    shown = agents[:15]
    for a in shown:
        seen = getattr(a, "last_seen", None)
        delta = (now - seen).total_seconds() if isinstance(seen, datetime) else None
        if delta is not None and delta < 300:
            icon, state = "\U0001F7E2", "online"
            online += 1
        elif delta is None:
            icon, state = "\u26AA", "never seen"
        else:
            icon, state = "\U0001F534", f"offline {_human_delta(delta)}"
        host = getattr(a, "hostname", None) or str(a.agent_id)[:8]
        kind = getattr(a, "agent_type", None) or "?"
        os_type = getattr(a, "os_type", None) or "?"
        # Una riga per dispositivo: host, che agente e' (Guard/NodeTrace),
        # sistema operativo e stato con l'ultimo contatto. "Chi e' online e su
        # cosa" e' l'unica domanda da telefono; il resto e' dashboard.
        rows.append(f"{icon} <b>{_esc(host)}</b> \u00b7 {_esc(kind)} \u00b7 "
                    f"{_esc(os_type)} \u00b7 {_esc(state)}")
    head = (f"\U0001F4E1 <b>Aegis</b> \u2014 {online} of {len(agents)} agents online\n"
            + "\u2500" * 18)
    tail = ""
    hidden = len(agents) - len(shown)
    if hidden > 0:
        tail = f"\n\u2026 and {hidden} more registered (dashboard for the full list)"
    return head + "\n" + "\n".join(rows) + tail


async def _cmd_alerts(db: AsyncSession) -> str:
    """Alert non risolti, filtrati con la STESSA soglia delle notifiche."""
    from app.database.models import Alert
    res = await db.execute(
        select(Alert).where(Alert.is_resolved.is_(False))
        .order_by(Alert.timestamp.desc()).limit(40))
    alerts = [a for a in res.scalars().all()
              if _severity_allows((getattr(a, "severity", "") or "").upper())]
    if not alerts:
        return ("\u2705 <b>Aegis</b> \u2014 no open alerts at or above "
                f"<code>{_esc(_min_severity())}</code>.")
    lines = []
    for a in alerts[:10]:
        sev = (getattr(a, "severity", "") or "?").upper()
        icon = SEVERITY_EMOJI.get(sev, "\u26AA")
        host = None
        try:
            host = await _hostname_for(db, str(getattr(a, "agent_id", "") or ""))
        except Exception:  # noqa: BLE001
            host = None
        lines.append(f"{icon} <b>#{_esc(a.id)}</b> {_esc(sev)} \u00b7 "
                     f"{_esc(host or 'host?')} \u00b7 {_esc(a.event_type or '?')}")
    head = (f"\u26A0\uFE0F <b>{len(alerts)} open alerts</b> "
            f"(threshold {_esc(_min_severity())})\n"
            + "\u2500" * 18)
    return head + "\n" + "\n".join(lines)


def _human_delta(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}g"


async def _handle_command(db: AsyncSession, text: str, chat_id: str) -> Optional[str]:
    """Risposta al comando, o None se non c'e' nulla da dire."""
    cmd = (text or "").strip().split()[0].lower() if (text or "").strip() else ""
    cmd = cmd.split("@")[0]  # Telegram: /status@nome_bot nei gruppi
    if cmd in ("/start", "/help", "help"):
        # /start risponde anche a chat non configurate: e' l'unico modo per
        # scoprire il proprio chat_id (nessun dato di sistema nel testo).
        return (_HELP + "\n" + "\u2500" * 18
                + f"\n\U0001F194 Your chat ID: <code>{_esc(chat_id)}</code>\n"
                  "Paste it in Settings \u2192 Telegram if you haven't yet.")
    if cmd in ("/status", "/alerts", "/agents"):
        configured = (app_settings.get_cached("telegram.chat_id") or "").strip()
        if not configured or str(chat_id) != configured:
            # Nessun dato a chi non e' autorizzato; nessuna conferma di cosa esiste.
            logger.warning("telegram: comando %s da chat non autorizzata", cmd)
            return None
        if cmd in ("/status", "/agents"):
            return await _cmd_status(db)
        return await _cmd_alerts(db)
    return None


async def _command_loop() -> None:
    """Long-poll dei comandi. Mai crash: un errore Telegram non tocca l'ingest."""
    # Nessun `global _known_chats` qui: la dict viene mutata da `_remember_chat`,
    # e una dichiarazione global senza assegnamento e' solo rumore (flake8 F824).
    offset = 0
    while True:
        db = None
        try:
            await asyncio.sleep(_commands_interval())
            db = _session_factory()
            await _ensure_cache(db)
            if not _is_enabled():
                continue
            token = await integration_settings.get_key(db, "telegram_bot_token")
            if not token:
                continue
            resp = await _get_updates(token, offset)
            if resp.status_code != 200:
                continue
            for update in resp.json().get("result", []):
                uid = update.get("update_id")
                if isinstance(uid, int):
                    offset = uid + 1
                msg = _remember_chat(update)
                if not msg:
                    continue
                reply = await _handle_command(db, msg.get("text") or "",
                                              str((msg.get("chat") or {}).get("id")))
                if reply:
                    await _send(token, str((msg.get("chat") or {}).get("id")), reply)
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001
            logger.exception("telegram: command loop error")
        finally:
            if db is not None:
                try:
                    await _db_cleanup(db)
                except Exception:  # noqa: BLE001
                    logger.exception("telegram: command db cleanup failed")


def _commands_interval() -> int:
    """Pausa fra due poll (secondi). Le notifiche non dipendono da questo giro:
    i comandi sono un extra, l'alert parte subito."""
    raw = (app_settings.get_cached("telegram.commands_poll_seconds") or "5").strip()
    try:
        return max(1, min(60, int(raw)))
    except ValueError:
        return 5


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
    """Avvia i task in background: heartbeat + polling dei comandi."""
    global _task, _cmd_task, _session_factory, _db_cleanup
    _session_factory = session_factory
    _db_cleanup = db_cleanup
    if _task is None or _task.done():
        _task = asyncio.create_task(_heartbeat_loop())
    # Il poll dei comandi parte insieme al heartbeat: sono due cose diverse
    # ("sono vivo" vs "rispondi a chi mi scrive") e un errore in uno non deve
    # fermare l'altro.
    if _cmd_task is None or _cmd_task.done():
        _cmd_task = asyncio.create_task(_command_loop())


async def stop_heartbeat() -> None:
    global _task, _cmd_task
    for task in (_task, _cmd_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    _task = None
    _cmd_task = None


_cmd_task: Optional[asyncio.Task] = None


_session_factory = None
_db_cleanup = None
