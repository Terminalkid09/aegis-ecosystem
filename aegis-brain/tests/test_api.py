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
        assert r.json()["version"] == "4.0.0"

@pytest.mark.asyncio
async def test_get_alerts_unauthorized():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/telemetry/alerts")
        assert r.status_code == 401

@pytest.mark.asyncio
async def test_get_alerts_authorized_jwt(client: AsyncClient, admin_auth_headers):
    r = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)

@pytest.mark.asyncio
async def test_alerts_list_exposes_evidence_and_hostname(client: AsyncClient,
                                                         admin_auth_headers,
                                                         db_session, test_agent):
    """La LISTA deve portare evidence e hostname, non solo il dettaglio.

    La tabella alert renderizza dalle righe di lista: la response_model
    List[AlertResponse] scartava i campi non dichiarati, quindi il pannello
    Evidence e il nome host non sarebbero mai comparsi in dashboard (bug
    trovato end-to-end, non dai test unitari).
    """
    from app.database.models import Alert

    alert = Alert(
        agent_id=test_agent.agent_id, severity="HIGH", process_name="system",
        event_type="behavioral_detection", description="test beacon",
        evidence={"source": "nodetrace", "ip": "104.16.4.34",
                  "connection_count": 27},
    )
    db_session.add(alert)
    await db_session.commit()

    r = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    items = [a for a in r.json() if a["id"] == alert.id]
    assert len(items) == 1
    row = items[0]
    assert row["evidence"]["ip"] == "104.16.4.34"
    assert row["evidence"]["connection_count"] == 27
    assert row["agent_hostname"] == test_agent.hostname


@pytest.mark.asyncio
async def test_get_alerts_rejects_api_key_only(client: AsyncClient, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "AEGIS_API_KEY", "test-secret-key")
    r = await client.get("/api/v1/telemetry/alerts", headers={"X-Api-Key": "test-secret-key"})
    assert r.status_code == 401
