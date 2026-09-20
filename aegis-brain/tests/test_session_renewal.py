"""Rinnovo della sessione: POST /auth/refresh.

Dietro questo endpoint c'e' il difetto in esercizio: sessione scaduta a meta'
lavoro -> re-login forzato -> dashboard freezata sullo stato vecchio. Il
rinnovo silenzioso lato client puo' esistere solo se il server sa rilasciare
una nuova identita' a chi ne ha gia' una valida.
"""
import pytest

pytestmark = pytest.mark.asyncio


async def test_refresh_renews_session(client, admin_auth_headers, admin_user):
    r = await client.post("/api/v1/auth/refresh", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("access_token"), "il rinnovo deve restituire un nuovo token"
    # Set-Cookie aggiornato
    assert "aegis_token=" in r.headers.get("set-cookie", "")
    # l'utente riconosciuto e' lo stesso
    assert body["user"]["id"] == admin_user.id


async def test_refresh_requires_auth(client):
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401


async def test_refresh_denied_for_disabled_account(client, admin_auth_headers):
    """Un account disattivato non puo' usarlo per prolungare la vita della sessione."""
    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    uid = next(u["id"] for u in r.json()["users"] if u["role"] == "admin")
    r = await client.patch(f"/api/v1/users/{uid}", json={"active": False},
                           headers=admin_auth_headers)
    if r.status_code == 409:  # last-admin protetto: uso un utente normale
        r = await client.post("/api/v1/auth/register", json={
            "username": "renewer", "email": "renewer@aegis.test", "password": "Str0ngPass!x"},
            headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        tok = r.json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        r2 = await client.get("/api/v1/users", headers=admin_auth_headers)
        uid2 = next(u["id"] for u in r2.json()["users"] if u["email"] == "renewer@aegis.test")
        await client.patch(f"/api/v1/users/{uid2}", json={"active": False},
                           headers=admin_auth_headers)
        r = await client.post("/api/v1/auth/refresh", headers=h)
        assert r.status_code == 401
