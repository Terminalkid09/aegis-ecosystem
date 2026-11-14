import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.core.config import settings
from app.database.models import Agent, AuditLog
import uuid


class TestEnrollment:
    async def test_enroll_success(self, client: AsyncClient, db_session):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": "new-host",
            "os": "linux",
            "machine_id": "machine-new-host",
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

    async def test_enroll_duplicate_hostname_os_without_token_is_denied(
            self, client: AsyncClient, db_session, test_agent):
        """AEGIS-SEC-001: la chiave statica non può sostituire un host esistente."""
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "machine_id": "machine-test-host",
            "enroll_key": settings.AGENT_ENROLL_KEY
        })
        assert response.status_code == 409
        audit = await db_session.execute(
            select(AuditLog).where(AuditLog.action == "agent_reenroll_denied"))
        assert audit.scalars().first() is not None

    async def test_reenroll_with_host_bound_token_succeeds_and_audits(
            self, client: AsyncClient, db_session, test_agent, admin_auth_headers):
        token_resp = await client.post(
            "/api/v1/deploy/token",
            json={"agent_type": "nodetrace",
                  "target_hostname": test_agent.hostname},
            headers=admin_auth_headers,
        )
        assert token_resp.status_code == 200
        raw_token = token_resp.json()["token"]
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "agent_type": "nodetrace",
            "machine_id": "machine-test-host",
            "enroll_key": raw_token,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "re-enrolled"
        assert data["agent_id"] == str(test_agent.agent_id)
        assert isinstance(data["agent_secret"], str) and data["agent_secret"]
        await db_session.refresh(test_agent)
        assert len(test_agent.meta["machine_id_hash"]) == 64
        audit = await db_session.execute(
            select(AuditLog).where(AuditLog.action == "agent_reenroll"))
        row = audit.scalars().first()
        assert row is not None
        assert row.details["token_target"] == test_agent.hostname

    async def test_reenroll_rejects_token_without_target_host(
            self, client: AsyncClient, db_session, test_agent, admin_auth_headers):
        token_resp = await client.post(
            "/api/v1/deploy/token",
            json={"agent_type": "nodetrace"},
            headers=admin_auth_headers,
        )
        assert token_resp.status_code == 200
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "agent_type": "nodetrace",
            "machine_id": "machine-test-host",
            "enroll_key": token_resp.json()["token"],
        })
        assert response.status_code == 409

    async def test_enroll_missing_fields(self, client: AsyncClient):
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": "test-host"
        })
        assert response.status_code == 422

    async def test_reenroll_revoked_denied(self, client: AsyncClient, db_session,
                                           test_agent, admin_auth_headers):
        # Revoca -> il re-enroll autonomo deve fallire chiuso (niente bypass
        # con token rubato). Riammissione solo manuale lato SOC.
        rev = await client.post(f"/api/v1/enroll/agents/{test_agent.agent_id}/revoke",
                                json={"reason": "test"}, headers=admin_auth_headers)
        assert rev.status_code == 200
        again = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "enroll_key": settings.AGENT_ENROLL_KEY
        })
        assert again.status_code == 403
        assert "revoked" in again.json()["detail"].lower()