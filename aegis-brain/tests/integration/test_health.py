import pytest
from httpx import AsyncClient


class TestHealth:
    async def test_liveness(self, client: AsyncClient):
        response = await client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "checks" in data

    async def test_readiness(self, client: AsyncClient):
        response = await client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["ready", "not_ready"]
        assert "checks" in data

    async def test_startup(self, client: AsyncClient):
        response = await client.get("/health/startup")
        assert response.status_code == 200

    async def test_circuit_breakers(self, client: AsyncClient):
        response = await client.get("/health/circuit-breakers")
        assert response.status_code == 200
        data = response.json()
        assert "ollama" in data
        assert "redis" in data
        assert "postgres" in data
        for breaker in data.values():
            assert "state" in breaker
            assert "fail_count" in breaker