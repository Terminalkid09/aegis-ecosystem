"""AEGIS-SEC-006: ciclo di vita della chiave via API admin."""
import pytest


@pytest.mark.asyncio
async def test_admin_can_create_list_and_revoke_api_key(client, admin_auth_headers):
    created = await client.post(
        "/api/v1/auth/api-keys",
        json={"name": "firewall-a", "source": "fw-a", "scopes": ["ingest"]},
        headers=admin_auth_headers,
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["api_key"].startswith("aegis_")
    assert body["source"] == "fw-a"
    key_id = body["id"]

    listed = await client.get("/api/v1/auth/api-keys", headers=admin_auth_headers)
    assert listed.status_code == 200, listed.text
    row = next(item for item in listed.json() if item["id"] == key_id)
    assert row["active"] is True
    assert row["source"] == "fw-a"
    assert "hashed_key" not in row

    revoked = await client.delete(f"/api/v1/auth/api-keys/{key_id}",
                                  headers=admin_auth_headers)
    assert revoked.status_code == 200, revoked.text

    after = await client.get("/api/v1/auth/api-keys", headers=admin_auth_headers)
    row = next(item for item in after.json() if item["id"] == key_id)
    assert row["active"] is False
    assert row["revoked_at"] is not None

    # La chiave non deve più autenticare l'ingestione.
    denied = await client.post(
        "/api/v1/ingest/fw-a", json={}, headers={"X-Api-Key": body["api_key"]})
    assert denied.status_code == 403, denied.text
