"""Il filtro alert che nascondeva la storia del triage.

Difetto osservato in UI: i resolved non apparivano mai. Due cause combinate:
1. la UI inviava `resolved=...` ma il backend leggeva solo `is_resolved`;
2. il default era `is_resolved=False`, cioe' "solo non risolti" per chiunque
   non passasse il parametro — la lista completa non era raggiungibile.

Proprieta' bloccate:
- il filtro funziona con entrambi i nomi (alias per compatibilita');
- senza filtro si vedono TUTTI gli alert (storia del triaggio visibile);
- i tre stati della UI restituiscono insiemi distinti e coerenti.
"""
import pytest


@pytest.mark.asyncio
async def test_filter_with_both_param_names(client, admin_auth_headers, test_agent, db_session):
    from app.services.telemetry_service import _suppressed
    from app.database.models import Alert
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    a1 = Alert(agent_id=test_agent.agent_id, severity="HIGH", event_type="PROCESS_CREATED",
               process_name="evil.exe", description="test", is_resolved=False, timestamp=now)
    a2 = Alert(agent_id=test_agent.agent_id, severity="LOW", event_type="PROCESS_CREATED",
               process_name="benign.exe", description="test", is_resolved=True, timestamp=now)
    db_session.add_all([a1, a2])
    await db_session.commit()

    r_new = await client.get("/api/v1/telemetry/alerts?is_resolved=false", headers=admin_auth_headers)
    r_old = await client.get("/api/v1/telemetry/alerts?resolved=false", headers=admin_auth_headers)
    assert r_new.status_code == r_old.status_code == 200, r_new.text
    ids_new = {a["id"] for a in r_new.json()}
    ids_old = {a["id"] for a in r_old.json()}
    assert ids_new == ids_old
    assert a1.id in ids_new and a2.id not in ids_new


@pytest.mark.asyncio
async def test_no_filter_shows_everything(client, admin_auth_headers, test_agent, db_session):
    from app.database.models import Alert
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    db_session.add_all([
        Alert(agent_id=test_agent.agent_id, severity="HIGH", event_type="PROCESS_CREATED",
              process_name="a.exe", description="test", is_resolved=False, timestamp=now),
        Alert(agent_id=test_agent.agent_id, severity="LOW", event_type="PROCESS_CREATED",
              process_name="b.exe", description="test", is_resolved=True, timestamp=now),
        Alert(agent_id=test_agent.agent_id, severity="MEDIUM", event_type="X", process_name="c.exe", description="test", timestamp=now),
    ])
    await db_session.commit()

    r = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    assert r.status_code == 200
    res = r.json()
    states = {a["id"]: a["is_resolved"] for a in res}
    assert res, "nessun alert restituito senza filtro"
    assert any(v is False or v is None for v in states.values())
    assert any(v is True for v in states.values())


@pytest.mark.asyncio
async def test_three_ui_states_are_distinct(client, admin_auth_headers, test_agent, db_session):
    from app.database.models import Alert
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    open_alert = Alert(agent_id=test_agent.agent_id, severity="HIGH",
                       event_type="PROCESS_CREATED", process_name="open.exe", description="test",
                       is_resolved=False, timestamp=now)
    done_alert = Alert(agent_id=test_agent.agent_id, severity="LOW",
                       event_type="PROCESS_CREATED", process_name="done.exe", description="test",
                       is_resolved=True, timestamp=now)
    db_session.add_all([open_alert, done_alert])
    await db_session.commit()

    r_open = await client.get("/api/v1/telemetry/alerts?is_resolved=false", headers=admin_auth_headers)
    r_done = await client.get("/api/v1/telemetry/alerts?is_resolved=true", headers=admin_auth_headers)
    r_all = await client.get("/api/v1/telemetry/alerts", headers=admin_auth_headers)
    ids_open = {a["id"] for a in r_open.json()}
    ids_done = {a["id"] for a in r_done.json()}
    ids_all = {a["id"] for a in r_all.json()}

    assert open_alert.id in ids_open and done_alert.id not in ids_open
    assert done_alert.id in ids_done and open_alert.id not in ids_done
    assert open_alert.id in ids_all and done_alert.id in ids_all
