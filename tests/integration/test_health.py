from httpx import AsyncClient
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import OperationalError


class TestHealth:
    async def test_health_simple(self, client: AsyncClient):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_health_detailed(self, client: AsyncClient):
        response = await client.get("/api/v1/health/detailed")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert "checks" in data

    async def test_health_database_unhealthy(self, client: AsyncClient):
        from app.main import app
        from app.db.session import get_db

        failing_session = AsyncMock(spec=AsyncSession)
        failing_session.execute.side_effect = OperationalError("Connection refused", None, None)

        async def override_get_db():
            yield failing_session

        app.dependency_overrides[get_db] = override_get_db
        try:
            response = await client.get("/api/v1/health/detailed")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
        finally:
            app.dependency_overrides.clear()

    async def test_metrics_endpoint(self, client: AsyncClient):
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "kraken_http_requests_total" in response.text
        assert "kraken_http_request_duration_seconds" in response.text
