import pytest
from httpx import AsyncClient
from app.core.config import settings
from app.database.models import Agent
import uuid


class TestEnrollment:
    async def test_enroll_success(self, client: AsyncClient, db_session):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": "new-host",
            "os": "linux",
            "enroll_key": settings.AGENT_ENROLL_KEY
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "enrolled"
        assert "agent_id" in data
        assert "agent_secret" in data
        assert data["agent_secret"] != "ALREADY_ENROLLED"

    async def test_enroll_invalid_key(self, client: AsyncClient):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": "new-host",
            "os": "linux",
            "enroll_key": "wrong-key"
        })
        assert response.status_code == 403

    async def test_enroll_duplicate_hostname_os(self, client: AsyncClient, db_session, test_agent):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "enroll_key": settings.AGENT_ENROLL_KEY
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "re-enrolled"
        assert isinstance(data["agent_secret"], str) and len(data["agent_secret"]) > 0
        assert data["agent_id"] == str(test_agent.agent_id)

    async def test_enroll_missing_fields(self, client: AsyncClient):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": "test-host"
        })
        assert response.status_code == 422