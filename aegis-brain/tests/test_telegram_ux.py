"""Telegram come telecomando: freschezza della config, formattazione, chiusure, comandi.

Proprieta' bloccate qui (ognuna nasce da un problema osservato):

- **config appena salvata = configurazione usabile subito**: si salvava il
  chat_id copiato da "Detect chat ID" e "Send test" rispondeva ancora "chat_id
  missing". Non era un ritardo di Telegram: era la cache in-process letta prima
  di essere invalidata (`send_test_message` leggeva la cache e solo dopo
  chiamava `_ensure_cache`). Un pulsante premuto dall'operatore non puo'
  dipendere da quando scade una cache.
- **messaggi leggibili**: prima un blocco unico di righe appiccicate; ora
  intestazione, righe etichettate, comando in monospazio e separatori. Con
  parse_mode=HTML i dati dell'endpoint DEVONO essere escapati: un `<` non
  neutralizzato fa rispondere 400 a Telegram e l'alert non parte.
- **chiusure notificate con la stessa soglia delle aperture**: chi sceglie
  CRITICAL non riceve ne' HIGH aperti ne' HIGH risolti. Una sola notifica per
  transizione (risolvere due volte non rimanda il messaggio).
- **comandi solo dal chat_id autorizzato**: `/status` e `/alerts` mostrano dati
  di sistema, quindi rispondono a una sola chat; `/start` risponde a chiunque
  perche' e' cosi' che si scopre il proprio chat_id (nessun dato di sistema).
"""
import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.database.models import Alert
from app.services import app_settings, integration_settings, telegram_notifier

FAKE_TOKEN = "123456:FAKE-TOKEN"


def _patch_token():
    return patch.object(integration_settings, "get_key",
                        new=AsyncMock(return_value=FAKE_TOKEN))


def _alert(sev="HIGH", etype="PROCESS_CREATED", name="evil.exe", agent=None):
    a = Alert(agent_id=agent.agent_id if agent else None, severity=sev,
              event_type=etype, process_name=name, description="test detection")
    a.timestamp = datetime.now(timezone.utc)
    return a


@pytest.fixture(autouse=True)
def _reset_notifier_state():
    telegram_notifier.invalidate_cache()
    # Le chat scoperte sono stato di processo, non config: senza azzerarle i
    # test si passano i residui l'un l'altro.
    telegram_notifier._known_chats.clear()
    logging.getLogger("aegis.telegram").propagate = True
    yield
    telegram_notifier.invalidate_cache()
    telegram_notifier._known_chats.clear()
    telegram_notifier._RESOLVED_SENT.clear()
    logging.getLogger("aegis.telegram").propagate = False


async def _enable(db, chat_id="12345", min_sev="HIGH"):
    """Config dal DB + seed della cache, come fanno gli altri test del notifier."""
    await app_settings.set_value(db, "telegram.enabled", "true")
    await app_settings.set_value(db, "telegram.chat_id", chat_id)
    await app_settings.set_value(db, "telegram.min_severity", min_sev)
    await db.flush()
    app_settings._TG_CACHE.clear()
    app_settings._TG_CACHE.update({
        app_settings.KEY_TG_ENABLED: "true",
        app_settings.KEY_TG_CHAT: chat_id,
        app_settings.KEY_TG_MIN_SEV: min_sev,
    })
    telegram_notifier._cache_loaded = True
    telegram_notifier._enabled = None


# ---------------------------------------------------------------------------
# Regressione: il chat_id salvato deve essere utilizzabile SUBITO
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chat_id_saved_is_usable_immediately(client, admin_auth_headers, db_session):
    """PUT poi POST /test, senza attese ne' refresh manuali: il contratto d'uso."""
    # `_send` e' l'unico punto di I/O: il pulsante "Send test" passa da li',
    # quindi mockarlo basta a rendere il test offline (prima il pulsante aveva
    # un client HTTP suo e il test chiamava Telegram per davvero).
    with _patch_token(), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(return_value=None)):
        r = await client.put("/api/v1/telegram/settings",
                             json={"enabled": True, "chat_id": "998877"},
                             headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        r = await client.post("/api/v1/telegram/test", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    assert app_settings.get_cached("telegram.chat_id") == "998877"


def test_invalidate_cache_clears_app_settings_cache():
    """Invalida anche la cache di app_settings: era quella il valore vecchio."""
    app_settings._TG_CACHE["telegram.chat_id"] = "vecchio"
    telegram_notifier.invalidate_cache()
    assert app_settings.get_cached("telegram.chat_id") is None


@pytest.mark.asyncio
async def test_test_message_reads_fresh_even_with_stale_cache(db_session):
    """La verifica di configurazione non dipende dall'eta' della cache."""
    await app_settings.set_value(db_session, "telegram.chat_id", "555111")
    await db_session.flush()
    app_settings._TG_CACHE.clear()
    app_settings._TG_CACHE["telegram.chat_id"] = ""
    telegram_notifier._cache_loaded = True

    posted = {}

    class _Resp:
        status_code = 200
        text = "ok"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            posted.update(json or {})
            return _Resp()

    with _patch_token(), patch("httpx.AsyncClient", lambda *a, **k: _Client()):
        out = await telegram_notifier.send_test_message(db_session)
    assert out["ok"] is True, out
    assert posted["chat_id"] == "555111"
    assert posted.get("parse_mode") == "HTML"


# ---------------------------------------------------------------------------
# Messaggi: separati e con escape HTML
# ---------------------------------------------------------------------------

def test_message_escapes_html_and_has_separators():
    a = _alert(sev="HIGH", etype="PROCESS_CREATED", name="a<b>.exe")
    a.process_path = "C:\\tmp\\<script>&x"
    a.command_line = "cmd /c echo <b>hi</b>"
    a.pid = 4321
    msg = telegram_notifier._format_message(telegram_notifier._alert_dict(a), "pc-1")
    assert "<b>HIGH</b>" in msg           # la nostra formattazione resta
    assert "a&lt;b&gt;.exe" in msg        # il dato dell'endpoint e' neutralizzato
    assert "<script>" not in msg
    assert "&amp;x" in msg
    assert "\u2500" in msg               # separatori: non piu' un blocco unico
    assert "pc-1" in msg and "HIGH" in msg


def test_resolved_message_marks_state():
    a = _alert(sev="CRITICAL", etype="PERSISTENCE", name="svc.exe")
    a.id = 77
    ok = telegram_notifier._format_resolved(telegram_notifier._alert_dict(a), "pc-1")
    again = telegram_notifier._format_resolved(telegram_notifier._alert_dict(a), "pc-1", True)
    assert "RESOLVED" in ok and "#77" in ok
    assert "REOPENED" in again


# ---------------------------------------------------------------------------
# Chiusure: stessa soglia delle aperture, una sola per transizione
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_notification_respects_threshold(client, db_session, test_agent):
    sent = []
    alert = _alert(sev="HIGH", agent=test_agent)
    alert.id = 4242
    db_session.add(alert)
    await db_session.flush()

    with _patch_token(), \
         patch.object(telegram_notifier, "_send",
                      new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await _enable(db_session, min_sev="HIGH")
        await telegram_notifier.notify_alert_resolved(db_session, alert)
        assert len(sent) == 1 and "RESOLVED" in sent[0]

        await telegram_notifier.notify_alert_resolved(db_session, alert)
        assert len(sent) == 1, "stessa transizione: nessun doppione"

        sent.clear()
        await _enable(db_session, min_sev="CRITICAL")
        await telegram_notifier.notify_alert_resolved(db_session, alert, reopened=True)
        assert sent == [], "sotto soglia la chiusura non deve arrivare"


@pytest.mark.asyncio
async def test_resolve_endpoint_triggers_notification(client, admin_auth_headers,
                                                     db_session, test_agent):
    """End-to-end: il resolve dalla dashboard e' cio' che genera il messaggio."""
    alert = _alert(sev="CRITICAL", agent=test_agent)
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)

    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_send",
                      new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await _enable(db_session, min_sev="HIGH")
        r = await client.patch(f"/api/v1/telemetry/alerts/{alert.id}/resolve",
                               json={"resolved": True}, headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    assert len(sent) == 1, "il resolve non ha notificato"
    assert "RESOLVED" in sent[0]


# ---------------------------------------------------------------------------
# Comandi: solo dal chat_id autorizzato
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_replies_with_chat_id_and_help(client, db_session, test_agent):
    """`/start` dice il proprio chat_id: e' il passo che rende usabile il setup."""
    reply = await telegram_notifier._handle_command(db_session, "/start", "777888")
    assert reply and "777888" in reply
    assert "/status" in reply and "/alerts" in reply


@pytest.mark.asyncio
async def test_status_from_authorized_chat_lists_agents(client, db_session, test_agent):
    await _enable(db_session, chat_id="12345", min_sev="HIGH")
    reply = await telegram_notifier._handle_command(db_session, "/status", "12345")
    assert reply is not None
    assert test_agent.hostname in reply


@pytest.mark.asyncio
async def test_alerts_command_filters_by_threshold(client, db_session, test_agent):
    """/alerts mostra solo cio' che sarebbe notificato: la soglia vale anche qui."""
    low = _alert(sev="LOW", agent=test_agent)
    high = _alert(sev="HIGH", agent=test_agent)
    db_session.add_all([low, high])
    await db_session.flush()
    await _enable(db_session, chat_id="12345", min_sev="HIGH")

    reply = await telegram_notifier._handle_command(db_session, "/alerts", "12345")
    assert reply is not None
    assert f"#{high.id}" in reply
    assert f"#{low.id}" not in reply


@pytest.mark.asyncio
async def test_commands_from_unauthorized_chat_get_nothing(client, db_session, test_agent):
    """Nessun dato a chat diverse: no leak, nessuna conferma di cosa esiste."""
    await _enable(db_session, chat_id="12345", min_sev="HIGH")
    assert await telegram_notifier._handle_command(db_session, "/status", "999") is None
    assert await telegram_notifier._handle_command(db_session, "/alerts", "999") is None


@pytest.mark.asyncio
async def test_unknown_command_is_silent(client, db_session, test_agent):
    await _enable(db_session, chat_id="12345", min_sev="HIGH")
    assert await telegram_notifier._handle_command(db_session, "/rm -rf", "12345") is None


@pytest.mark.asyncio
async def test_command_with_bot_suffix_is_accepted(client, db_session, test_agent):
    """/status@nome_bot e' come Telegram presenta i comandi nei gruppi."""
    await _enable(db_session, chat_id="12345", min_sev="HIGH")
    assert await telegram_notifier._handle_command(db_session, "/status@aegis_bot", "12345")


@pytest.mark.asyncio
async def test_command_loop_marks_updates_as_handled(client, db_session, test_agent):
    """Il loop conferma gli update (offset) e risponde: mai riprocessare gli stessi."""
    await _enable(db_session, chat_id="12345", min_sev="HIGH")

    update = {"update_id": 41, "message": {
        "message_id": 1, "date": 0,
        "chat": {"id": 12345, "type": "private", "first_name": "Ily"},
        "text": "/help",
    }}
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"result": [update]}

    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_get_updates",
                      new=AsyncMock(return_value=resp)) as upd, \
         patch.object(telegram_notifier, "_send",
                      new=AsyncMock(side_effect=lambda t, c, x: sent.append((t, c, x)))), \
         patch.object(telegram_notifier, "_commands_interval", lambda: 0), \
         patch.object(telegram_notifier, "_session_factory", lambda: db_session), \
         patch.object(telegram_notifier, "_db_cleanup", AsyncMock()):
        import asyncio
        task = asyncio.create_task(telegram_notifier._command_loop())
        for _ in range(200):
            await asyncio.sleep(0.01)
            if sent:
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert sent, "il comando non ha ricevuto risposta"
    assert sent[0][1] == "12345"
    assert "Aegis" in sent[0][2]
    # offset = update_id + 1: senza, Telegram rimanda sempre lo stesso comando.
    assert upd.await_args_list[-1].args[-1] == 42
