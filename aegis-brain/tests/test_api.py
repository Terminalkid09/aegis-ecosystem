import os
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
        # No X-Api-Key header
        r = await client.get("/api/v1/telemetry/alerts")
        assert r.status_code == 403

@pytest.mark.asyncio
async def test_get_alerts_authorized(db_session):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Api-Key": "test-secret-key"}
        r = await client.get("/api/v1/telemetry/alerts", headers=headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)
