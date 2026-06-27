import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_root():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["version"] == "2.0.0"

@pytest.mark.asyncio
async def test_get_alerts_unauthorized():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/telemetry/alerts")
        assert r.status_code == 401

@pytest.mark.asyncio
async def test_get_alerts_authorized_jwt(client: AsyncClient, admin_auth_headers):
    r = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)

@pytest.mark.asyncio
async def test_get_alerts_rejects_api_key_only(client: AsyncClient, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "AEGIS_API_KEY", "test-secret-key")
    r = await client.get("/api/v1/telemetry/alerts", headers={"X-Api-Key": "test-secret-key"})
    assert r.status_code == 401
