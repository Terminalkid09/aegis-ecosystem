import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.core.config import settings
from app.core.security import verify_device_token_proof
from app.database.models import Agent, AuditLog, EnrollToken
from app.services import pki
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
        agent = await db_session.get(Agent, uuid.UUID(data["agent_id"]))
        assert agent is not None
        assert verify_device_token_proof(
            data["agent_secret"], agent.device_token_hash,
            (agent.meta or {}).get("device_token_proof"),
        )

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
            json={"agent_type": "unified",
                  "target_hostname": test_agent.hostname},
            headers=admin_auth_headers,
        )
        assert token_resp.status_code == 200
        raw_token = token_resp.json()["token"]
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "agent_type": "unified",
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
        assert verify_device_token_proof(
            data["agent_secret"], test_agent.device_token_hash,
            test_agent.meta.get("device_token_proof"),
        )
        audit = await db_session.execute(
            select(AuditLog).where(AuditLog.action == "agent_reenroll"))
        row = audit.scalars().first()
        assert row is not None
        assert row.details["token_target"] == test_agent.hostname

    async def test_reenroll_rejects_token_without_target_host(
            self, client: AsyncClient, db_session, test_agent, admin_auth_headers):
        token_resp = await client.post(
            "/api/v1/deploy/token",
            json={"agent_type": "unified"},
            headers=admin_auth_headers,
        )
        assert token_resp.status_code == 200
        response = await client.post("/api/v1/enroll/enroll", json={
            "hostname": test_agent.hostname,
            "os": test_agent.os_type,
            "agent_type": "unified",
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
        await db_session.refresh(test_agent)
        assert "device_token_proof" not in (test_agent.meta or {})

    async def test_unified_mode_is_carried_into_token_and_job(
            self, client: AsyncClient, db_session, admin_auth_headers):
        """One agent record, but the selected capability is explicit end to end."""
        pki.ensure_manifest_key(settings.PKI_DIR)
        last_raw = ""
        for mode in ("full", "sensor", "endpoint"):
            response = await client.post(
                "/api/v1/deploy/token",
                json={"agent_type": "unified", "agent_mode": mode},
                headers=admin_auth_headers,
            )
            assert response.status_code == 200
            body = response.json()
            assert body["agent_type"] == "unified"
            assert body["agent_mode"] == mode
            assert f"mode={mode}" in body["oneline_windows"]
            assert f"mode={mode}" in body["oneline_linux"]
            if mode == "sensor":
                last_raw = body["token"]

        install = await client.get(
            "/api/v1/deploy/install.sh?agent=unified&mode=sensor",
            headers={"X-Enroll-Token": last_raw},
        )
        assert install.status_code == 200
        assert 'AGENT_MODE="sensor"' in install.text
        assert "AEGIS_AGENT_MODE=$AGENT_MODE" in install.text
        wrong_mode = await client.get(
            "/api/v1/deploy/install.sh?agent=unified&mode=full",
            headers={"X-Enroll-Token": last_raw},
        )
        assert wrong_mode.status_code == 403

        token = (await db_session.execute(
            select(EnrollToken).order_by(EnrollToken.id.desc()))).scalars().first()
        assert token is not None and token.install_config["agent_mode"] == "endpoint"

        job = await client.post(
            "/api/v1/deploy/jobs",
            json={
                "agent_type": "unified", "agent_mode": "sensor",
                "method_default": "oneline",
                "targets": [{"ip_address": "10.42.0.10"}],
            },
            headers=admin_auth_headers,
        )
        assert job.status_code == 200
        data = job.json()
        assert data["status"] == "manual_required"
        assert data["agent_mode"] == "sensor"
        result = data["targets"] and data["targets"][0]
        assert result["method"] == "oneline"

        fetched = await client.get(
            f"/api/v1/deploy/jobs/{data['job_id']}",
            headers=admin_auth_headers,
        )
        assert fetched.status_code == 200
        assert fetched.json()["results"]["10.42.0.10"]["agent_mode"] == "sensor"

    async def test_deploy_rejects_ssh_and_credentials(
            self, client: AsyncClient, admin_auth_headers):
        ssh = await client.post(
            "/api/v1/deploy/jobs",
            json={"method_default": "ssh", "targets": [{"ip_address": "10.42.0.11"}]},
            headers=admin_auth_headers,
        )
        assert ssh.status_code == 422
        creds = await client.post(
            "/api/v1/deploy/jobs",
            json={"username": "root", "password": "secret",
                  "targets": [{"ip_address": "10.42.0.11"}]},
            headers=admin_auth_headers,
        )
        assert creds.status_code == 400