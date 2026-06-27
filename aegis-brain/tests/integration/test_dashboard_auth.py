import pytest
from httpx import AsyncClient


class TestDashboardJwtAuth:
    async def test_telemetry_stats_requires_jwt(self, client: AsyncClient):
        response = await client.get("/api/v1/telemetry/stats")
        assert response.status_code == 401

    async def test_telemetry_stats_with_jwt(self, client: AsyncClient, admin_auth_headers):
        response = await client.get("/api/v1/telemetry/stats", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data

    async def test_api_key_no_longer_grants_dashboard_access(self, client: AsyncClient, monkeypatch):
        from app.core.config import settings
        monkeypatch.setattr(settings, "AEGIS_API_KEY", "legacy-dashboard-key")
        response = await client.get(
            "/api/v1/telemetry/agents",
            headers={"X-Api-Key": "legacy-dashboard-key"},
        )
        assert response.status_code == 401
