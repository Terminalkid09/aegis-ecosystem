import os
import uuid
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import get_db
from app.database.models import Agent, Alert
from app.core.security import hash_password, verify_password
from sqlalchemy import select
from app.services.anomaly_engine import anomaly_engine

@pytest.mark.asyncio
async def test_anomaly_detection_creates_alert(db_session):
    anomaly_engine.window_size = 10
    anomaly_engine.min_samples = 5
    anomaly_engine.threshold = 2.0

    agent_id = uuid.uuid4()
    token = "agent-secret-token"
    agent = Agent(agent_id=agent_id, hostname="t1", device_token_hash=hash_password(token))
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    headers = {
        "X-Agent-Id": str(agent_id),
        "Authorization": f"Bearer {token}"
    }

    async def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(6):
            payload = {
                "agent_id": str(agent_id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "METRICS_REPORT",
                "cpu_usage": 5.0 + i
            }
            r = await client.post("/api/v1/telemetry/report", json=payload, headers=headers)
            assert r.status_code == 200

        payload_spike = {
            "agent_id": str(agent_id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "METRICS_REPORT",
            "cpu_usage": 99.0
        }
        r = await client.post("/api/v1/telemetry/report", json=payload_spike, headers=headers)
        assert r.status_code == 200

    app.dependency_overrides.clear()

    result = await db_session.execute(select(Alert).where(Alert.agent_id == agent_id, Alert.event_type == "statistical_anomaly"))
    alerts = result.scalars().all()
    assert len(alerts) >= 1
