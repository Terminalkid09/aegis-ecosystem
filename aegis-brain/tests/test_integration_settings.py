"""Chiavi di integrazione: catalogo dinamico, mascheramento, permessi,
precedenza env->DB e uso effettivo della chiave nelle lookup OSINT.

La risoluzione runtime è la parte che non deve mai reggersi su coincidenze:
se l'env vince, il DB non conta; se il provider non ha chiave, la lookup
restituisce `api_key_not_configured` e non esplode.
"""
import pytest

from app.core.config import settings
from app.core.crypto import encrypt_value, decrypt_value
from app.services import integration_settings as isvc
from app.services import osint_service


def _clear_osint_env(monkeypatch):
    """L'host di sviluppo ha chiavi OSINT reali nell'env: vincono sempre sul DB
    (precedenza dichiarata). I test di risoluzione devono partire da env neutro."""
    monkeypatch.setattr(settings, "SHODAN_API_KEY", "")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")


# ------------------------------------------------------------------ crypto

def test_encrypt_value_roundtrip():
    token = encrypt_value("sk-test-123")
    assert token != "sk-test-123"
    assert decrypt_value(token) == "sk-test-123"


def test_plain_marker_when_no_master_key(monkeypatch):
    monkeypatch.setattr(settings, "MASTER_KEY_B64", None)
    assert decrypt_value(encrypt_value("abc")) == "abc"


# ---------------------------------------------------------------- catalogo

@pytest.mark.asyncio
async def test_status_masks_and_never_exposes_key(db_session, monkeypatch):
    _clear_osint_env(monkeypatch)
    monkeypatch.setattr(settings, "SHODAN_API_KEY", "envkey1234567890abcd")
    await isvc.set_key(db_session, "abuseipdb", "dbkey9876543210zyxw", updated_by=None)
    await db_session.commit()

    provs = {p["key"]: p for p in await isvc.get_provider_status(db_session)}
    assert provs["shodan"]["source"] == "env"
    assert provs["shodan"]["active"] is True
    assert provs["shodan"]["overridable"] is False  # env vince: DB non conta
    assert provs["abuseipdb"]["source"] == "database"
    assert "envkey1234567890abcd" not in str(provs)
    assert "dbkey9876543210zyxw" not in str(provs)
    assert provs["abuseipdb"]["masked"].endswith("zyxw")
    assert provs["abuseipdb"]["masked"].isascii()  # la maschera finisce in log/console Windows: ASCII puro
    assert provs["virustotal"]["source"] == "not set"
    assert provs["virustotal"]["active"] is False


@pytest.mark.asyncio
async def test_env_wins_over_db(db_session, monkeypatch):
    _clear_osint_env(monkeypatch)
    monkeypatch.setattr(settings, "SHODAN_API_KEY", "envkey1234567890abcd")
    await isvc.set_key(db_session, "shodan", "dbkey9876543210zyxw", updated_by=None)
    await db_session.commit()
    assert await isvc.get_key(db_session, "shodan") == "envkey1234567890abcd"


@pytest.mark.asyncio
async def test_db_used_when_no_env(db_session, monkeypatch):
    _clear_osint_env(monkeypatch)
    await isvc.set_key(db_session, "shodan", "dbkey9876543210zyxw", updated_by=None)
    await db_session.commit()
    assert await isvc.get_key(db_session, "shodan") == "dbkey9876543210zyxw"


@pytest.mark.asyncio
async def test_set_empty_clears_override(db_session, monkeypatch):
    _clear_osint_env(monkeypatch)
    from sqlalchemy import select
    from app.database.models import IntegrationSetting
    await isvc.set_key(db_session, "shodan", "temp", updated_by=None)
    await db_session.commit()
    await isvc.set_key(db_session, "shodan", "", updated_by=None)
    await db_session.commit()
    assert await isvc.get_key(db_session, "shodan") == ""
    rows = (await db_session.execute(select(IntegrationSetting))).scalars().all()
    assert all(r.key != "shodan" for r in rows)


def test_placeholder_rejected_as_env_value():
    # Le chiavi segnaposto dell'env non contano come chiave reale.
    assert isvc._placeholder("your_shodan_key_here")
    assert not isvc._placeholder("real-key-123")


@pytest.mark.asyncio
async def test_unknown_provider_has_no_key(db_session):
    # get_key su provider sconosciuto = vuoto, mai eccezione.
    assert await isvc.get_key(db_session, "unknown") == ""


# ------------------------------------------------------ API + permessi

@pytest.mark.asyncio
async def test_api_requires_manage(client, user_auth_headers, admin_auth_headers, monkeypatch):
    _clear_osint_env(monkeypatch)
    # user (ruolo user) -> 403
    r = await client.put("/api/v1/integrations/settings",
                         json={"provider": "shodan", "value": "k123"},
                         headers=user_auth_headers)
    assert r.status_code == 403
    # anonimo -> 401
    r = await client.get("/api/v1/integrations/settings")
    assert r.status_code == 401
    # admin -> 200
    r = await client.put("/api/v1/integrations/settings",
                         json={"provider": "shodan", "value": "k123456789"},
                         headers=admin_auth_headers)
    assert r.status_code == 200
    # provider sconosciuto -> 400
    r = await client.put("/api/v1/integrations/settings",
                         json={"provider": "nope", "value": "x"},
                         headers=admin_auth_headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_api_status_no_key_leak(client, admin_auth_headers, monkeypatch):
    _clear_osint_env(monkeypatch)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "supersecretkey9999")
    r = await client.get("/api/v1/integrations/settings", headers=admin_auth_headers)
    assert r.status_code == 200
    body = str(r.json())
    assert "supersecretkey9999" not in body
    assert "..." in body and "..." not in "supersecretkey9999"  # mascherato ASCII (con ellissi intermedie)


# --------------------------------------- uso effettivo nelle lookup OSINT

@pytest.mark.asyncio
async def test_lookup_uses_db_key(monkeypatch):
    """Senza env, la chiave salvata in DB deve arrivare all'header HTTP."""
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    captured = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"data": {"abuseConfidenceScore": 90, "totalReports": 5}}

    class FakeClient:
        async def get(self, url, headers=None, params=None, timeout=None):
            captured["headers"] = headers
            return FakeResp()

    async def fake_get_key(session, name):
        return "dbkey-from-database"

    monkeypatch.setattr(osint_service, "_provider_key", fake_get_key)
    result = await osint_service._abuseipdb_lookup(FakeClient(), "8.8.8.8", None)
    assert result["abuseConfidenceScore"] == 90
    assert captured["headers"]["Key"] == "dbkey-from-database"


@pytest.mark.asyncio
async def test_lookup_without_key_is_clean_error(monkeypatch):
    async def fake_get_key(session, name):
        return ""
    monkeypatch.setattr(osint_service, "_provider_key", fake_get_key)
    result = await osint_service._shodan_lookup(None, "8.8.8.8", None)
    assert result == {"error": "api_key_not_configured"}
