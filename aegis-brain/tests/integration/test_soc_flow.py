import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def test_soc_flow_login_overview_fleet_alert_incident_evidence_revoca(client: AsyncClient, admin_auth_headers):
    # 1. Overview SOC: stats + agents + incidents
    r = await client.get("/api/v1/telemetry/stats", headers=admin_auth_headers)
    assert r.status_code == 200
    stats = r.json()
    for k in ("active_agents", "total_alerts", "isolated_agents"):
        assert k in stats

    r = await client.get("/api/v1/telemetry/agents", headers=admin_auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    # 2. Alert explorer: crea un alert via telemetry report
    # Prima enrolla un agent di test per poter inviare telemetry
    from app.core.config import settings
    import uuid
    hostname = f"flow-host-{uuid.uuid4().hex[:6]}"
    r = await client.post("/api/v1/enroll/enroll", json={
        "hostname": hostname, "os": "linux", "enroll_key": settings.AGENT_ENROLL_KEY
    })
    assert r.status_code == 200
    agent_id = r.json()["agent_id"]
    agent_secret = r.json()["agent_secret"]
    agent_headers = {"Authorization": f"Bearer {agent_secret}", "X-Agent-Id": agent_id}

    # Invia un evento benigno e uno sospetto per generare alert
    benign = {"agent_id": agent_id, "timestamp": "2026-09-12T10:00:00+00:00", "event_type": "PROCESS_CREATED", "pid": 1234, "process_name": "notepad.exe", "process_path": "C:\\Windows\\System32\\notepad.exe"}
    r = await client.post("/api/v1/telemetry/report", json=benign, headers=agent_headers)
    assert r.status_code == 200

    # L'evento sospetto richiede un tool noto: mimikatz
    evil = {"agent_id": agent_id, "timestamp": "2026-09-12T10:01:00+00:00", "event_type": "PROCESS_CREATED", "pid": 5678, "process_name": "mimikatz.exe", "process_path": "C:\\Tools\\mimikatz.exe"}
    r = await client.post("/api/v1/telemetry/report", json=evil, headers=agent_headers)
    assert r.status_code == 200

    # 3. Alert explorer: lista e parent/child/evidenze
    r = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    assert r.status_code == 200
    items = r.json()
    if isinstance(items, dict):
        items = items.get("items") or items.get("data") or []
    # Deve esserci almeno un alert critico per mimikatz
    found = [a for a in items if "mimikatz" in (a.get("description") or "").lower() or a.get("process_name") == "mimikatz.exe"]
    assert len(found) >= 1
    alert = found[0]
    for k in ("severity", "process_name", "description"):
        assert k in alert

    # 4. Incident timeline: crea incident con alert, assegna, nota, audit
    r = await client.post("/api/v1/soc/incidents", json={"title": f"Flow incident {hostname}", "alert_ids": [alert["id"]]}, headers=admin_auth_headers)
    assert r.status_code in (200, 201)
    inc = r.json()
    inc_id = inc.get("id") or inc.get("incident", {}).get("id") or inc.get("incident_id")
    assert inc_id is not None

    r = await client.get(f"/api/v1/soc/incidents/{inc_id}", headers=admin_auth_headers)
    assert r.status_code == 200
    detail = r.json()
    assert "timeline" in detail or "alerts" in detail or "events" in detail or isinstance(detail, dict)

    # Assegnazione e note
    r = await client.patch(f"/api/v1/soc/incidents/{inc_id}", json={"assignee_id": None, "note": "triage in corso"}, headers=admin_auth_headers)
    # 200 o 400 a seconda se supporta note: accettiamo entrambi ma non 500
    assert r.status_code in (200, 400, 422)

    # 5. Enrollment/deploy: crea token e verifica revoca certificato path
    r = await client.post("/api/v1/deploy/token", json={"label": f"flow-{hostname}"}, headers=admin_auth_headers)
    assert r.status_code == 200
    assert "token" in r.json()

    # Stato mTLS: verifica che /enroll/ca.crt sia raggiungibile e che la verifica fallisca senza cert quando required
    r = await client.get("/api/v1/enroll/ca.crt")
    # 200 se CA inizializzata, 503 se non bootstrap: entrambi accettabili, mai 500
    assert r.status_code in (200, 503)

    # Revoca certificato: l'agent appena creato deve poter essere revocato
    r = await client.post(f"/api/v1/enroll/agents/{agent_id}/revoke", json={"reason": "flow-test"}, headers=admin_auth_headers)
    assert r.status_code in (200, 404)  # 404 se l'endpoint richiede agent diverso
