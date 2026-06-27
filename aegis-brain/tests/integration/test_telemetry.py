import pytest
from httpx import AsyncClient
from app.database.models import Agent, Alert, Telemetry
from datetime import datetime, timezone
import uuid


class TestTelemetry:
    async def test_get_alerts(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        for i in range(3):
            db_session.add(Alert(
                agent_id=test_agent.agent_id,
                severity="HIGH" if i % 2 == 0 else "MEDIUM",
                process_name=f"process_{i}",
                event_type="PROCESS_CREATED",
                description=f"Suspicious activity {i}",
            ))
        await db_session.commit()

        response = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    async def test_get_alerts_filter_severity(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        db_session.add(Alert(
            agent_id=test_agent.agent_id, severity="CRITICAL",
            process_name="critical_proc", event_type="PROCESS_CREATED", description="Critical"
        ))
        db_session.add(Alert(
            agent_id=test_agent.agent_id, severity="LOW",
            process_name="low_proc", event_type="PROCESS_CREATED", description="Low"
        ))
        await db_session.commit()

        response = await client.get("/api/v1/telemetry/alerts?severity=CRITICAL", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["severity"] == "CRITICAL"

    async def test_resolve_alert(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        alert = Alert(
            agent_id=test_agent.agent_id, severity="HIGH", pid=1234,
            process_name="malicious", event_type="PROCESS_CREATED",
            description="Test alert", is_resolved=False
        )
        db_session.add(alert)
        await db_session.commit()
        await db_session.refresh(alert)

        response = await client.patch(f"/api/v1/telemetry/alerts/{alert.id}/resolve",
                                     json={"resolved": True}, headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["is_resolved"] is True

    async def test_get_agents(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        response = await client.get("/api/v1/telemetry/agents", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(a["hostname"] == "test-host" for a in data)

    async def test_get_recent_telemetry(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        db_session.add(Telemetry(
            device_id=test_agent.agent_id,
            cpu_usage=45.5, ram_usage=60.2,
            disk_free=100000000, disk_total=500000000,
        ))
        await db_session.commit()

        response = await client.get("/api/v1/telemetry/recent", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert data[0]["cpu_usage"] == 45.5

    async def test_get_activity(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        db_session.add(Telemetry(
            device_id=test_agent.agent_id, cpu_usage=10.0, ram_usage=20.0
        ))
        db_session.add(Alert(
            agent_id=test_agent.agent_id, severity="MEDIUM",
            process_name="test", event_type="TEST", description="Test"
        ))
        await db_session.commit()

        response = await client.get("/api/v1/telemetry/activity", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2
        types = {item["type"] for item in data}
        assert "telemetry" in types
        assert "alert" in types

    async def test_get_stats(self, client: AsyncClient, admin_auth_headers, db_session, test_agent):
        for i in range(5):
            db_session.add(Alert(
                agent_id=test_agent.agent_id,
                severity=["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOW"][i],
                process_name=f"proc_{i}", event_type="TEST", description=f"Desc {i}",
                is_resolved=i < 2
            ))
        await db_session.commit()

        response = await client.get("/api/v1/telemetry/stats", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_alerts"] == 5
        assert data["unresolved_alerts"] == 3
        assert data["current_critical_alerts"] == 1
        assert data["current_high_alerts"] == 1

    async def test_agent_report(self, client: AsyncClient, agent_auth_headers, test_agent):
        response = await client.post("/api/v1/telemetry/report", headers=agent_auth_headers, json={
            "agent_id": str(test_agent.agent_id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "METRICS_REPORT",
            "cpu_usage": 50.0,
            "ram_usage": 70.0,
            "hostname": "test-host",
        })
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_agent_heartbeat(self, client: AsyncClient, agent_auth_headers, test_agent):
        response = await client.post("/api/v1/telemetry/heartbeat", headers=agent_auth_headers, json={
            "device_id": str(test_agent.agent_id)
        })
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_get_agent_commands(self, client: AsyncClient, agent_auth_headers, test_agent):
        response = await client.get("/api/v1/telemetry/commands", headers=agent_auth_headers)
        assert response.status_code == 200