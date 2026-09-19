"""Notifiche Telegram: il guardiano che parla quando la dashboard e' chiusa.

Proprieta' bloccate:
- solo HIGH/CRITICAL notificano (il rumore LOW/MEDIUM resta in dashboard);
- spento di default: senza config esplicita NESSUN messaggio lascia la rete;
- cooldown: una raffica di alert uguali non flooda la chat;
- config via API admin-gated, con validazione chat_id/min_severity;
- fail-soft: un errore di invio non rompe mai l'ingest.
"""
import logging

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock

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
    # Surface swallowed errors: il notifier e' fail-soft per contratto, ma in
    # test un'eccezione silenziosa e' un bug invisibile (gia' successo: su CI
    # i test positivi fallivano con sent==[] e nessun traceback nei log).
    logging.getLogger("aegis.telegram").propagate = True
    yield
    telegram_notifier.invalidate_cache()
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
async def test_low_medium_never_notified(client, db_session, test_agent):
    """LOW/MEDIUM non partono nemmeno con il notifier attivo."""
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
    """PUT con chat_id/Severita' invalidi = 400; validi = aggiornati."""
    r = await client.put("/api/v1/telegram/settings",
                         json={"chat_id": "not valid!!"}, headers=admin_auth_headers)
    assert r.status_code == 400

    r = await client.put("/api/v1/telegram/settings",
                         json={"min_severity": "LOW"}, headers=admin_auth_headers)
    assert r.status_code == 400

    r = await client.put("/api/v1/telegram/settings",
                         json={"heartbeat_minutes": 5}, headers=admin_auth_headers)
    assert r.status_code == 400

    r = await client.put("/api/v1/telegram/settings",
                         json={"enabled": True, "chat_id": "-1009988",
                               "min_severity": "CRITICAL", "heartbeat_minutes": 30},
                         headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["changed"]["enabled"] is True

    r = await client.get("/api/v1/telegram/settings", headers=admin_auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["chat_id"] == "-1009988"
    assert body["min_severity"] == "CRITICAL"
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
