import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.database.models import Agent, Telemetry
from app.core.security import hash_password
import uuid


class TestNodeTraceDeepTelemetry:
    async def test_update_persists_users_and_network_flows(
        self, client: AsyncClient, db_session, admin_auth_headers,
    ):
        agent_id = uuid.uuid4()
        token = "nt-test-token-abc"
        agent = Agent(
            agent_id=agent_id,
            hostname="deep-telemetry-host",
            os_type="windows",
            agent_type="nodetrace",
            device_token_hash=hash_password(token),
        )
        db_session.add(agent)
        await db_session.commit()

        payload = {
            "device_id": str(agent_id),
            "cpu_usage": 12.5,
            "ram_usage": 34.0,
            "processes": [{"name": "explorer.exe", "pid": 1234}],
            "users": [{"username": "alice", "active": True}],
            "network_flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "port": 443}],
        }
        response = await client.post(
            "/api/v1/update",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

        result = await db_session.execute(
            select(Telemetry).where(Telemetry.device_id == agent_id)
        )
        row = result.scalars().first()
        assert row is not None
        assert row.users == [{"username": "alice", "active": True}]
        assert row.network_flows == [{"src": "10.0.0.1", "dst": "8.8.8.8", "port": 443}]

        recent = await client.get("/api/v1/telemetry/recent", headers=admin_auth_headers)
        assert recent.status_code == 200
        items = recent.json()
        assert any(item.get("cpu_usage") == 12.5 for item in items)

    async def test_nodetrace_register_and_update_flow(self, client: AsyncClient, db_session):
        from app.core.config import settings

        reg = await client.post("/api/v1/register", json={
            "hostname": f"e2e-host-{uuid.uuid4().hex[:8]}",
            "os": "linux",
            "enroll_key": settings.AGENT_ENROLL_KEY,
        })
        assert reg.status_code == 200
        data = reg.json()
        assert "device_id" in data
        assert data.get("device_token") not in (None, "ALREADY_REGISTERED")

        device_id = data["device_id"]
        token = data["device_token"]
        update = await client.post("/api/v1/update", json={
            "device_id": device_id,
            "cpu_usage": 5.0,
            "ram_usage": 10.0,
            "processes": [{"name": "systemd", "pid": 1}],
            "users": [{"username": "root"}],
            "network_flows": [{"proto": "tcp", "port": 22}],
        }, headers={"Authorization": f"Bearer {token}"})
        assert update.status_code == 200

        hb = await client.post("/api/v1/heartbeat", json={"device_id": device_id},
                               headers={"Authorization": f"Bearer {token}"})
        assert hb.status_code == 200

        cmds = await client.get(
            "/api/v1/commands",
            params={"device_id": device_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert cmds.status_code == 200
