"""Flusso "Mantieni l'accesso su questo dispositivo" (remember-me).

Copre i punti che fanno la differenza tra un remember-me giocattolo e uno
sicuro: il cookie contiene solo un token opaco (l'hash sta sul server), ogni
uso lo RUOTA (il replay di un cookie rubato muore), la revoca del dispositivo
uccide il trust, e il logout da una macchina condivisa finisce ANCHE il trust.

Gli utenti nascono direttamente nel DB (non via /register): il rate-limit di
register e' globale per IP e i test non devono competersi.
"""
import pytest

from app.core.config import settings
from app.core.security import hash_password
from app.database.models import User

REMEMBER_COOKIE = "aegis_remember"
SESSION_COOKIE = "aegis_token"

# Il middleware CSRF esige un Origin consentito su ogni richiesta mutante
# autenticata via cookie: nel flusso remember e' proprio cosi' che vive.
ORIGIN = {"Origin": "http://localhost:3000"}

_next_id = iter(range(9000, 9900))


async def _make_user(db_session, name: str) -> User:
    user = User(
        username=name,
        email=f"{name}@aegis.test",
        password_hash=hash_password("Str0ngPass!x"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture(autouse=True)
def _insecure_cookies_for_http_client(monkeypatch):
    """Il client di test parla http: con COOKIE_SECURE=true il cookie jar di
    Python non invierebbe mai i cookie (Secure = solo https) e il flusso
    remember sembrerebbe rotto pur funzionando su un deploy https reale."""
    monkeypatch.setattr(settings, "COOKIE_SECURE", False)


@pytest.mark.asyncio
async def test_login_without_remember_sets_no_trust(client, db_session):
    """Default: nessun cookie remember. Il trust e' solo opt-in."""
    user = await _make_user(db_session, "noremember")
    r = await client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Str0ngPass!x"}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert client.cookies.get(REMEMBER_COOKIE) is None


@pytest.mark.asyncio
async def test_remember_flow_issue_silent_login_and_rotation(client, db_session):
    """login(remember=True) -> cookie -> logout -> /auth/remember rientra
    senza credenziali e ruota il token (il vecchio non vale piu')."""
    user = await _make_user(db_session, "rememberme")

    r = await client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Str0ngPass!x",
        "remember": True}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    raw_first = client.cookies.get(REMEMBER_COOKIE)
    assert raw_first, "il login con remember deve emettere il cookie"

    # La sessione sparisce: il remember basta da solo per rientrare.
    client.cookies.delete(SESSION_COOKIE)
    r = await client.post("/api/v1/auth/remember", headers=ORIGIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["email"] == user.email
    assert client.cookies.get(SESSION_COOKIE), "il remember rinnova la sessione"

    # Rotazione: il token consumato non vale piu' (replay = 401). Il cookie
    # "nuovo" arriva nel Set-Cookie della chiamata precedente: lo salvo PRIMA
    # di rimettere quello vecchio nel jar (come farebbe un attaccante col
    # cookie rubato: sovrascrive, ma la vittima conserva il suo).
    raw_second = client.cookies.get(REMEMBER_COOKIE)
    assert raw_second and raw_second != raw_first, "il token deve essere ruotato"
    client.cookies.set(REMEMBER_COOKIE, raw_first)
    r = await client.post("/api/v1/auth/remember", headers=ORIGIN)
    assert r.status_code == 401

    # Il nuovo token invece funziona ancora.
    client.cookies.set(REMEMBER_COOKIE, raw_second)
    r = await client.post("/api/v1/auth/remember", headers=ORIGIN)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_devices_list_and_revoke_kill_trust(client, db_session):
    """La revoca dal pannello dispositivi invalida il cookie ricordato."""
    user = await _make_user(db_session, "devicectl")
    r = await client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Str0ngPass!x",
        "remember": True}, headers=ORIGIN)
    assert r.status_code == 200

    r = await client.get("/api/v1/auth/devices")
    assert r.status_code == 200, r.text
    devices = r.json()
    assert len(devices) >= 1
    device = devices[0]
    assert device["revoked"] is False
    assert device["device_label"]  # etichetta human-readable dallo user-agent

    r = await client.delete(f"/api/v1/auth/devices/{device['id']}", headers=ORIGIN)
    assert r.status_code == 200

    client.cookies.delete(SESSION_COOKIE)
    r = await client.post("/api/v1/auth/remember", headers=ORIGIN)
    assert r.status_code == 401, "il trust revocato non rientra"


@pytest.mark.asyncio
async def test_logout_ends_trust(client, db_session):
    """Logout su macchina condivisa: la sessione AND il trust muoiono."""
    user = await _make_user(db_session, "sharedpc")
    r = await client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Str0ngPass!x",
        "remember": True}, headers=ORIGIN)
    assert r.status_code == 200

    r = await client.post("/api/v1/auth/logout", headers=ORIGIN)
    assert r.status_code == 200
    assert client.cookies.get(REMEMBER_COOKIE) is None, \
        "il logout deve cancellare anche il cookie remember"

    r = await client.post("/api/v1/auth/remember", headers=ORIGIN)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_remember_cookie_path_restricted_and_flags(client, db_session):
    """Il cookie remember: HttpOnly + SameSite strict + path ristretto ad auth."""
    user = await _make_user(db_session, "cookieflag")
    r = await client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Str0ngPass!x",
        "remember": True}, headers=ORIGIN)
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/api/v1/auth" in set_cookie
