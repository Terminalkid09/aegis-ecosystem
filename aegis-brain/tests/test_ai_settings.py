"""Impostazioni AI dalla dashboard: catalogo, precedenza, permessi, effetto.

La parte che non deve reggersi su coincidenze e' la PRECEDENZA: un valore
esplicito nel `.env` vince, `AI_PROVIDER=auto` (che e' il default del compose,
non una scelta) non blocca la dashboard, e il consenso all'arricchimento
automatico cloud e' spento a meno che qualcuno lo accenda. Un errore qui non
si vede: si vede solo che "l'AI non cambia mai" o, peggio, che gli alert
escono verso un provider cloud senza che nessuno l'abbia chiesto.
"""
import pytest

from app.core.config import settings
from app.services import ai_service
from app.services import app_settings as apsvc


def _clear_ai_env(monkeypatch):
    """Env neutro: i test partono dal default, non da cio' che c'e' sulla macchina."""
    monkeypatch.setattr(settings, "AI_PROVIDER", "auto")
    monkeypatch.setattr(settings, "AI_MODEL", "")
    monkeypatch.setattr(settings, "AI_AUTOMATIC_ENRICH", False)


# ------------------------------------------------------------------ catalogo

def test_provider_catalog_is_validated():
    assert apsvc.validate_provider("ollama") is True
    assert apsvc.validate_provider("gemini") is True
    assert apsvc.validate_provider("nope") is False
    # Le etichette della UI esistono per ogni valore selezionabile: un valore
    # senza etichetta renderebbe un'opzione cieca nel selettore.
    for value in apsvc.AI_PROVIDERS:
        assert value in apsvc.PROVIDER_LABELS, value


def test_default_models_are_declared_per_provider():
    models = apsvc.default_models()
    assert models["gemini"] == settings.GEMINI_MODEL
    assert models["openai"] == settings.OPENAI_MODEL
    assert models["ollama"] == settings.OLLAMA_DEFAULT_MODEL


# ----------------------------------------------------------------- storage

@pytest.mark.asyncio
async def test_set_and_clear_roundtrip(db_session):
    assert await apsvc.get_value(db_session, apsvc.KEY_PROVIDER) is None

    assert await apsvc.set_value(db_session, apsvc.KEY_PROVIDER, "ollama", None) is True
    await db_session.commit()
    assert await apsvc.get_value(db_session, apsvc.KEY_PROVIDER) == "ollama"

    # Stringa vuota = torna al default: la riga sparisce, non resta vuota.
    await apsvc.set_value(db_session, apsvc.KEY_PROVIDER, "", None)
    await db_session.commit()
    assert await apsvc.get_value(db_session, apsvc.KEY_PROVIDER) is None


@pytest.mark.asyncio
async def test_unknown_key_is_refused(db_session):
    assert await apsvc.set_value(db_session, "ai.not_a_key", "x", None) is False
    assert await apsvc.get_value(db_session, "ai.not_a_key") is None


# --------------------------------------------------------------- precedenza

@pytest.mark.asyncio
async def test_auto_env_does_not_block_the_dashboard(db_session, monkeypatch):
    """`AI_PROVIDER=auto` e' il default del compose, non una scelta: se vincesse
    sempre, il selettore in dashboard sarebbe decorativo."""
    _clear_ai_env(monkeypatch)
    await apsvc.set_value(db_session, apsvc.KEY_PROVIDER, "gemini", None)
    await db_session.commit()

    cfg = await apsvc.resolve_ai(db_session)
    assert cfg["provider"] == "gemini"
    assert cfg["provider_source"] == "database"


@pytest.mark.asyncio
async def test_explicit_env_wins_over_dashboard(db_session, monkeypatch):
    _clear_ai_env(monkeypatch)
    await apsvc.set_value(db_session, apsvc.KEY_PROVIDER, "gemini", None)
    await apsvc.set_value(db_session, apsvc.KEY_MODEL, "gemini-1.5-pro", None)
    await db_session.commit()

    monkeypatch.setattr(settings, "AI_PROVIDER", "disabled")
    monkeypatch.setattr(settings, "AI_MODEL", "modello-da-env")
    cfg = await apsvc.resolve_ai(db_session)
    assert (cfg["provider"], cfg["provider_source"]) == ("disabled", "env")
    assert (cfg["model"], cfg["model_source"]) == ("modello-da-env", "env")


@pytest.mark.asyncio
async def test_defaults_when_nothing_is_configured(db_session, monkeypatch):
    _clear_ai_env(monkeypatch)
    cfg = await apsvc.resolve_ai(db_session)
    assert cfg["provider"] == "auto"
    assert cfg["provider_source"] == "default"
    assert cfg["model"] == ""
    assert cfg["model_source"] == "default"
    assert cfg["automatic_enrich"] is False


@pytest.mark.asyncio
async def test_cloud_automatic_enrichment_is_opt_in(db_session, monkeypatch):
    """Il consenso cloud: il dashboad value vince, e il default e' spento."""
    _clear_ai_env(monkeypatch)
    assert (await apsvc.resolve_ai(db_session))["automatic_enrich"] is False

    await apsvc.set_value(db_session, apsvc.KEY_AUTOMATIC, "true", None)
    await db_session.commit()
    cfg = await apsvc.resolve_ai(db_session)
    assert cfg["automatic_enrich"] is True
    assert cfg["automatic_source"] == "database"


def _fake_config(**overrides):
    """Config risolta, iniettata al posto della lettura dal DB.

    `resolve_provider` legge le impostazioni dalla connessione vera (corretto
    in produzione: la dashboard scrive sul DB che il brain legge), quindi in un
    unit test non e' iniettabile da una sessione di test. Il cablaggio si
    verifica qui iniettando `_ai_config`; il percorso reale DB -> runtime e'
    coperto end-to-end contro lo stack vivo (`PUT /api/v1/ai/settings` +
    `GET /api/v1/ai/status`, e il check "impostazioni AI" in api_smoke.py).
    """
    base = {"provider": "auto", "provider_source": "default", "model": "",
            "model_source": "default", "automatic_enrich": False,
            "automatic_source": "database", "cloud": False, "local": False}
    base.update(overrides)

    async def _cfg(*_a, **_k):
        return base
    return _cfg


@pytest.mark.asyncio
async def test_local_provider_is_automatic_without_consent(monkeypatch):
    """Ollama: niente esce dalla rete, quindi nessun consenso da chiedere."""
    _clear_ai_env(monkeypatch)
    monkeypatch.setattr(settings, "OLLAMA_URL", "http://127.0.0.1:1/api/generate")
    monkeypatch.setattr(ai_service, "_ai_config",
                        _fake_config(provider="ollama", provider_source="database",
                                     local=True))
    info = await ai_service.resolve_provider()
    assert info["provider"] == "ollama"
    assert info["automatic"] is True
    # Il server non risponde: lo stato lo deve DIRE, non far finta che vada tutto bene.
    assert info["reachable"] is False
    assert "not reachable" in info["reason"]


@pytest.mark.asyncio
async def test_cloud_without_key_degrades_explicitly(monkeypatch):
    _clear_ai_env(monkeypatch)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(ai_service, "_ai_config",
                        _fake_config(provider="gemini", provider_source="database",
                                     cloud=True))
    info = await ai_service.resolve_provider()
    assert info["provider"] == "disabled"
    assert "no API key" in info["reason"]


@pytest.mark.asyncio
async def test_dashboard_choice_drives_runtime_resolution(monkeypatch):
    """Cio' che la dashboard ha scelto decide il provider a runtime, non solo in UI."""
    _clear_ai_env(monkeypatch)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(ai_service, "_ai_config",
                        _fake_config(provider="gemini", provider_source="database",
                                     cloud=True))
    info = await ai_service.resolve_provider()
    assert info["provider"] == "disabled"
    assert "gemini" in info["reason"]


@pytest.mark.asyncio
async def test_config_read_failure_falls_back_to_env(monkeypatch):
    """DB irraggiungibile: la risoluzione NON esplode, ricade sull'env.

    E' la differenza fra "l'AI e' disattivata" e "il brain risponde 500 a ogni
    arricchimento" quando il DB ha un singhiozzo.
    """
    _clear_ai_env(monkeypatch)
    monkeypatch.setattr(settings, "AI_PROVIDER", "disabled")

    class _Boom:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            raise RuntimeError("db down")

        async def __aexit__(self, *_a):
            return False

    import app.database.connection as conn
    monkeypatch.setattr(conn, "AsyncSessionLocal", _Boom)

    info = await ai_service.resolve_provider()
    assert info["provider"] == "disabled"
    assert info["reason"] == "disabled by configuration"


# ------------------------------------------------------------------- API

@pytest.mark.asyncio
async def test_get_settings_payload(client, admin_auth_headers):
    r = await client.get("/api/v1/ai/settings", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    values = {p["value"] for p in body["providers"]}
    assert {"auto", "disabled", "ollama", "gemini", "openai"} <= values
    assert body["current"]["provider_source"] in {"env", "database", "default"}
    assert "status" in body
    assert set(body["default_models"]) >= {"ollama", "gemini", "openai"}


@pytest.mark.asyncio
async def test_put_rejects_unknown_provider(client, admin_auth_headers):
    r = await client.put("/api/v1/ai/settings", json={"provider": "skynet"},
                         headers=admin_auth_headers)
    assert r.status_code == 400, r.text
    assert "skynet" in r.text


@pytest.mark.asyncio
async def test_put_requires_authentication(client):
    r = await client.put("/api/v1/ai/settings", json={"provider": "disabled"})
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_put_as_regular_user_is_forbidden(client, user_auth_headers):
    """Non e' una preferenza utente: decide se gli alert possono uscire dalla rete."""
    r = await client.put("/api/v1/ai/settings", json={"provider": "disabled"},
                         headers=user_auth_headers)
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_put_then_read_back(client, admin_auth_headers, db_session, monkeypatch):
    _clear_ai_env(monkeypatch)
    r = await client.put("/api/v1/ai/settings",
                         json={"provider": "ollama", "model": "qwen2.5:14b",
                               "automatic_enrich": True},
                         headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current"]["provider"] == "ollama"
    assert body["current"]["model"] == "qwen2.5:14b"
    assert body["current"]["provider_source"] == "database"
    assert body["changed"]["provider"] == "ollama"

    # Scrivere "auto" RIPULISCE l'override: auto e' il default della
    # piattaforma, non un valore da tenere salvato con origine "dashboard".
    r2 = await client.put("/api/v1/ai/settings", json={"provider": "auto"},
                          headers=admin_auth_headers)
    assert r2.status_code == 200, r2.text
    assert r2.json()["current"]["provider_source"] == "default"
    assert await apsvc.get_value(db_session, apsvc.KEY_PROVIDER) is None


@pytest.mark.asyncio
async def test_settings_are_audited(client, admin_auth_headers):
    """Un cambio di postura AI deve lasciare traccia: chi, cosa, quando.

    Chi decide se il contenuto degli alert puo' uscire dalla rete deve essere
    ricostruibile a posteriori; senza audit resta solo la configurazione.
    """
    r = await client.put("/api/v1/ai/settings", json={"provider": "gemini"},
                         headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    try:
        resp = await client.get("/api/v1/audit/logs?action=ai_settings_set&limit=10",
                                headers=admin_auth_headers)
        assert resp.status_code == 200, resp.text
        logs = resp.json()
        assert logs, "nessun record di audit per un cambio di postura AI"
        assert any((e.get("details") or {}).get("provider") == "gemini"
                   for e in logs), logs
    finally:
        # Non si lascia la piattaforma (e il DB di test) con un provider
        # scelto da un test.
        await client.put("/api/v1/ai/settings", json={"provider": "auto"},
                         headers=admin_auth_headers)
