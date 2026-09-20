"""Notifiche Telegram: il guardiano che parla quando la dashboard e' chiusa.

Proprieta' bloccate:
- la soglia minima e' CONFIGURABILE (INFO..CRITICAL), default HIGH: spento di
  default e senza config esplicita NESSUN messaggio lascia la rete, e col
  default il rumore LOW/MEDIUM resta in dashboard (comportamento invariato);
- cooldown: una raffica di alert uguali non flooda la chat;
- config via API admin-gated, con validazione chat_id (@publicname incluso,
  era rotto dal lstrip) e min_severity su tutta la scala;
- detect: i chat_id scoperti via getUpdates, senza indovinare;
- fail-soft: un errore di invio non rompe mai l'ingest.
"""
import logging

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock

from app.database.models import Alert
from app.services import telegram_notifier, app_settings, integration_settings

FAKE_TOKEN = "123456:FAKE-TOKEN"  # formato valido, ma il punto HTTP e' mockato


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
    # Le chat scoperte sono stato di PROCESSO (le tiene il poll dei comandi,
    # che le consuma da getUpdates): senza azzerarle ogni test si porta dietro
    # le chat dei precedenti e i test di `detect` — che verificano cosa viene
    # restituito ADESSO — falliscono su residui, non su un bug.
    telegram_notifier._known_chats.clear()
    # Surface swallowed errors: il notifier e' fail-soft per contratto, ma in
    # test un'eccezione silenziosa e' un bug invisibile (gia' successo: su CI
    # i test positivi fallivano con sent==[] e nessun traceback nei log).
    logging.getLogger("aegis.telegram").propagate = True
    yield
    telegram_notifier.invalidate_cache()
    telegram_notifier._known_chats.clear()
    logging.getLogger("aegis.telegram").propagate = False


async def _enable(db, chat_id="12345", min_sev="HIGH"):
    """Config dal DB + seed deterministico della cache del notifier.

    Il seed diretto rende i test positivi indipendenti dal lazy-load (già
    coperto end-to-end da test_settings_endpoint_validation): ciò che qui si
    verifica sono le soglie, il cooldown e il formato del messaggio.
    """
    await app_settings.set_value(db, "telegram.enabled", "true")
    await app_settings.set_value(db, "telegram.chat_id", chat_id)
    await app_settings.set_value(db, "telegram.min_severity", min_sev)
    await db.flush()  # autoflush=False nella sessione di test: senza flush la cache non vede le righe
    app_settings._TG_CACHE.clear()
    app_settings._TG_CACHE.update({
        app_settings.KEY_TG_ENABLED: "true",
        app_settings.KEY_TG_CHAT: chat_id,
        app_settings.KEY_TG_MIN_SEV: min_sev,
    })
    telegram_notifier._cache_loaded = True
    telegram_notifier._enabled = None


@pytest.mark.asyncio
async def test_disabled_by_default_no_send(client, db_session, test_agent):
    """Senza enable esplicito nessun invio: la notifica e' opt-in."""
    sent = []
    with patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))
    assert sent == []


@pytest.mark.asyncio
async def test_low_medium_never_notified_with_default_threshold(client, db_session, test_agent):
    """Con la soglia di default (HIGH) LOW/MEDIUM non partono nemmeno attivi."""
    await _enable(db_session)
    sent = []
    with patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(sev="LOW", agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(sev="MEDIUM", agent=test_agent))
    assert sent == []


@pytest.mark.asyncio
async def test_high_alert_notified_and_cooldown(client, db_session, test_agent):
    """HIGH notificato una volta; il secondo identico entro il cooldown no."""
    await _enable(db_session)
    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))
    assert len(sent) == 1
    assert "HIGH" in sent[0]
    assert "evil.exe" in sent[0]
    assert "Aegis" in sent[0]


@pytest.mark.asyncio
async def test_first_alert_after_boot_is_not_cooldown_blocked(client, db_session, test_agent):
    """Regressione CI: uptime macchina < cooldown non deve silenziare il primo alert.

    Il cooldown era inizializzato con default 0 su time.monotonic(): su un
    runner appena avviato now - 0 < 600 e l'alert di sempre veniva scartato
    in silenzio. "Mai inviato" ora e' None, non 0.
    """
    await _enable(db_session)
    telegram_notifier._last_sent.clear()  # nessun invio precedente
    fake_monotonic = 120.0  # uptime simulato basso, come su un runner CI
    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier.time, "monotonic", return_value=fake_monotonic), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))
    assert len(sent) == 1, "il primo alert dopo l'avvio deve sempre partire"


@pytest.mark.asyncio
async def test_min_severity_critical_filters_high(client, db_session, test_agent):
    """Con min_severity=CRITICAL gli HIGH restano silenziosi."""
    await _enable(db_session, min_sev="CRITICAL")
    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(sev="HIGH", agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(sev="CRITICAL", agent=test_agent))
    assert len(sent) == 1
    assert "CRITICAL" in sent[0]


@pytest.mark.asyncio
async def test_min_severity_medium_notifies_medium_blocks_low(client, db_session, test_agent):
    """Soglia MEDIUM: MEDIUM arriva, LOW/INFO no (la scala è ordinata)."""
    await _enable(db_session, min_sev="MEDIUM")
    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(sev="LOW", agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(sev="INFO", agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(sev="MEDIUM", agent=test_agent))
    assert len(sent) == 1
    assert "MEDIUM" in sent[0]


@pytest.mark.asyncio
async def test_min_severity_info_notifies_everything(client, db_session, test_agent):
    """Soglia INFO: anche LOW passa (scelta dell'operatore, non più cablata)."""
    await _enable(db_session, min_sev="INFO")
    sent = []
    with _patch_token(), \
         patch.object(telegram_notifier, "_send", new=AsyncMock(side_effect=lambda t, c, x: sent.append(x))):
        await telegram_notifier.notify_alert(db_session, _alert(sev="LOW", agent=test_agent))
        await telegram_notifier.notify_alert(db_session, _alert(sev="CRITICAL", agent=test_agent))
    assert len(sent) == 2


@pytest.mark.asyncio
async def test_missing_token_skips_gracefully(client, db_session, test_agent):
    """Enabled ma senza token: skip con warning, mai un'eccezione."""
    await _enable(db_session)
    # nessun token in integration_settings: notify non deve sollevare
    await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))


@pytest.mark.asyncio
async def test_send_failure_is_soft(client, db_session, test_agent):
    """Errore di rete su _send: notify non propaga l'eccezione."""
    await _enable(db_session)
    with _patch_token(), \
         patch.object(telegram_notifier, "_send",
                      new=AsyncMock(side_effect=ConnectionError("boom"))):
        await telegram_notifier.notify_alert(db_session, _alert(agent=test_agent))


@pytest.mark.asyncio
async def test_settings_endpoint_validation(client, admin_auth_headers, db_session):
    """PUT con valori invalidi = 400; validi (tutta la scala + @publicname) = 200."""
    r = await client.put("/api/v1/telegram/settings",
                         json={"chat_id": "not valid!!"}, headers=admin_auth_headers)
    assert r.status_code == 400

    # @publicname DEVE essere accettato (bug storico: lstrip("@") + startswith
    # su un valore già privato del @ = condizione mai vera, sempre 400).
    r = await client.put("/api/v1/telegram/settings",
                         json={"chat_id": "@aegis_alerts"}, headers=admin_auth_headers)
    assert r.status_code == 200, r.text

    # min_severity su tutta la scala: LOW ora è VALIDO, il default resta HIGH.
    r = await client.put("/api/v1/telegram/settings",
                         json={"min_severity": "LOW"}, headers=admin_auth_headers)
    assert r.status_code == 200, r.text

    r = await client.put("/api/v1/telegram/settings",
                         json={"min_severity": "EXTREME"}, headers=admin_auth_headers)
    assert r.status_code == 400

    r = await client.put("/api/v1/telegram/settings",
                         json={"heartbeat_minutes": 5}, headers=admin_auth_headers)
    assert r.status_code == 400

    r = await client.put("/api/v1/telegram/settings",
                         json={"enabled": True, "chat_id": "-1009988",
                               "min_severity": "MEDIUM", "heartbeat_minutes": 30},
                         headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["changed"]["enabled"] is True

    r = await client.get("/api/v1/telegram/settings", headers=admin_auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["chat_id"] == "-1009988"
    assert body["min_severity"] == "MEDIUM"
    assert body["heartbeat_minutes"] == 30


@pytest.mark.asyncio
async def test_settings_require_manage(client, user_auth_headers):
    """Un utente senza permessi manage non cambia la postura di notifica."""
    r = await client.put("/api/v1/telegram/settings",
                         json={"enabled": True}, headers=user_auth_headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_message_format_contains_core_fields(db_session, test_agent):
    """Il messaggio porta host, evento, processo e MITRE quando presente."""
    a = _alert(sev="CRITICAL", etype="CREDENTIAL_DUMPING", name="mimidog.exe", agent=test_agent)
    a.mitre_technique_id = "T1003"
    a.mitre_technique_name = "OS Credential Dumping"
    msg = telegram_notifier._format_message(telegram_notifier._alert_dict(a), "dev-pc")
    assert "dev-pc" in msg
    assert "CREDENTIAL_DUMPING" in msg
    assert "mimidog.exe" in msg
    assert "T1003" in msg


# ---------------------------------------------------------------------------
# Detect chat_id via getUpdates: il bottone toglie l'indovinello
# ---------------------------------------------------------------------------


def _tg_resp(payload=None, status_code=200):
    """httpx.Response-like: .status_code/.text attributi, .json() sincrono."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = str(payload or "")
    resp.json.return_value = payload if payload is not None else {}
    return resp


def _tg_update(chat_id, username="ilysm", first="Ily"):
    return {"update_id": 1, "message": {
        "message_id": 1, "date": 0,
        "chat": {"id": chat_id, "type": "private",
                 "first_name": first, "username": username},
        "text": "/start",
    }}


@pytest.mark.asyncio
async def test_detect_returns_chats_that_messaged_the_bot(client, admin_auth_headers):
    """Detect elenca le chat trovate con id, nome e tipo."""
    resp = _tg_resp({"result": [_tg_update(424242)]})
    with _patch_token(), \
         patch.object(telegram_notifier, "_get_updates", new=AsyncMock(return_value=resp)):
        r = await client.post("/api/v1/telegram/detect", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    chats = r.json()["chats"]
    assert len(chats) == 1
    assert chats[0]["id"] == 424242
    assert chats[0]["username"] == "ilysm"


@pytest.mark.asyncio
async def test_detect_with_no_messages_gives_hint(client, admin_auth_headers):
    """Nessuna chat: ok=True ma con l'istruzione (scrivi al bot e riprova)."""
    resp = _tg_resp({"result": []})
    with _patch_token(), \
         patch.object(telegram_notifier, "_get_updates", new=AsyncMock(return_value=resp)):
        r = await client.post("/api/v1/telegram/detect", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["chats"] == []
    assert "send your bot" in r.json()["hint"]


@pytest.mark.asyncio
async def test_detect_without_token_is_502_with_clear_detail(client, admin_auth_headers):
    """Senza token: 502 col messaggio che dice dove rimediare."""
    r = await client.post("/api/v1/telegram/detect", headers=admin_auth_headers)
    assert r.status_code == 502
    assert "bot token missing" in r.json()["detail"]


@pytest.mark.asyncio
async def test_detect_requires_manage(client, user_auth_headers):
    """Il detect espone chat esistenti: serve il permesso manage."""
    r = await client.post("/api/v1/telegram/detect", headers=user_auth_headers)
    assert r.status_code == 403
