"""Gestione account: enforcement del flag `active` e protezione last-admin.

Il flag esisteva ma non veniva controllato da nessuno: qui si verifica che
login e token di un account disattivato muoiano subito, che solo il ruolo
`manage` tocchi gli utenti, e che il sistema non possa restare senza admin.
"""
import pytest

pytestmark = pytest.mark.asyncio


async def _create_user(client, email, username="victim"):
    r = await client.post("/api/v1/auth/register", json={
        "username": username, "email": email, "password": "Str0ngPass!x"})
    assert r.status_code == 200, r.text
    return r.json()


async def test_disabled_user_cannot_login(client, admin_auth_headers):
    await _create_user(client, "disableme@aegis.test")
    r = await client.patch("/api/v1/users/1", json={}, headers=admin_auth_headers)
    # sanity: PATCH senza campi -> 422, l'endpoint esiste e risponde
    assert r.status_code == 422

    # trova l'id via elenco admin
    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    uid = next(u["id"] for u in r.json()["users"] if u["email"] == "disableme@aegis.test")

    # disattiva
    r = await client.patch(f"/api/v1/users/{uid}", json={"active": False},
                           headers=admin_auth_headers)
    assert r.status_code == 200 and r.json()["active"] is False, r.text

    # login con credenziali CORRETTE -> 403, non 401 (non e' un problema di password)
    r = await client.post("/api/v1/auth/login", json={
        "email": "disableme@aegis.test", "password": "Str0ngPass!x"})
    assert r.status_code == 403
    assert "disabled" in r.json()["detail"].lower()


async def test_disabled_user_token_revoked_immediately(client, admin_auth_headers):
    data = await _create_user(client, "revokeme@aegis.test", username="revokeme")
    headers = {"Authorization": f"Bearer {data['access_token']}"}

    # il token funziona finché l'account è attivo
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 200, r.text

    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    uid = next(u["id"] for u in r.json()["users"] if u["email"] == "revokeme@aegis.test")
    r = await client.patch(f"/api/v1/users/{uid}", json={"active": False},
                           headers=admin_auth_headers)
    assert r.status_code == 200

    # stessa identica sessione, nessun re-login: il token perde valore SUBITO
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 401


async def test_users_endpoint_requires_manage_perm(client, user_auth_headers):
    r = await client.get("/api/v1/users", headers=user_auth_headers)
    assert r.status_code == 403
    r = await client.patch("/api/v1/users/1", json={"active": False},
                           headers=user_auth_headers)
    assert r.status_code == 403
    # senza auth proprio
    r = await client.get("/api/v1/users")
    assert r.status_code == 401


async def test_cannot_disable_last_active_admin(client, admin_auth_headers):
    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    admins = [u for u in r.json()["users"] if u["role"] == "admin" and u["active"]]
    assert len(admins) >= 1
    if len(admins) > 1:
        pytest.skip("piu' di un admin attivo: la protezione non e' esercitabile qui")
    uid = admins[0]["id"]
    r = await client.patch(f"/api/v1/users/{uid}", json={"active": False},
                           headers=admin_auth_headers)
    assert r.status_code == 409
    assert "last active admin" in r.json()["detail"]
    # stessa protezione per il downgrade di ruolo
    r = await client.patch(f"/api/v1/users/{uid}", json={"role": "user"},
                           headers=admin_auth_headers)
    assert r.status_code == 409


async def test_unknown_role_rejected(client, admin_auth_headers):
    await _create_user(client, "roletarget@aegis.test", username="roletarget")
    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    uid = next(u["id"] for u in r.json()["users"] if u["email"] == "roletarget@aegis.test")
    r = await client.patch(f"/api/v1/users/{uid}", json={"role": "supreme-leader"},
                           headers=admin_auth_headers)
    assert r.status_code == 422


async def test_reactivate_user_restores_access(client, admin_auth_headers):
    await _create_user(client, "roundtrip@aegis.test", username="roundtrip")
    r = await client.get("/api/v1/users", headers=admin_auth_headers)
    uid = next(u["id"] for u in r.json()["users"] if u["email"] == "roundtrip@aegis.test")

    r = await client.patch(f"/api/v1/users/{uid}", json={"active": False},
                           headers=admin_auth_headers)
    assert r.status_code == 200 and r.json()["active"] is False
    r = await client.post("/api/v1/auth/login", json={
        "email": "roundtrip@aegis.test", "password": "Str0ngPass!x"})
    assert r.status_code == 403

    r = await client.patch(f"/api/v1/users/{uid}", json={"active": True},
                           headers=admin_auth_headers)
    assert r.status_code == 200 and r.json()["active"] is True
    r = await client.post("/api/v1/auth/login", json={
        "email": "roundtrip@aegis.test", "password": "Str0ngPass!x"})
    assert r.status_code == 200, r.text
