"""Contract and ordering tests for the unified SOC timeline."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.database.models import Agent, Alert, Incident, SiemEvent, Telemetry
from app.services.timeline import SOURCE_NAMES, query_timeline


def test_source_allowlist_is_exactly_the_five_documented_sources():
    assert SOURCE_NAMES == ("siem", "deception", "alert", "incident", "telemetry")


@pytest.mark.asyncio
async def test_timeline_merges_five_sources_in_descending_order(db_session):
    now = datetime.now(timezone.utc)
    agent_id = uuid4()
    db_session.add(Agent(
        agent_id=agent_id, hostname="sensor-e2e", os_type="linux", agent_type="nodetrace",
        last_seen=now,
    ))
    db_session.add_all([
        SiemEvent(
            time=now - timedelta(minutes=5), source="firewall", source_type="firewall",
            event_id="evt-1", severity="MEDIUM", message="allowed outbound", hostname="sensor-e2e",
        ),
        SiemEvent(
            time=now - timedelta(minutes=4), source="kraken", source_type="kraken",
            event_id="kraken-1", severity="HIGH", message="SSH login attempt",
            hostname="kraken-sensor", src_ip="203.0.113.10",
            extra={"kraken": {"sensor": "ssh", "session_id": "s-1", "context": "lab"}},
        ),
        Alert(
            agent_id=agent_id, timestamp=now - timedelta(minutes=3), severity="HIGH",
            process_name="sshd", event_type="auth_failure", description="brute force",
        ),
        Incident(
            title="Credential access", severity="CRITICAL", status="open",
            agent_id=str(agent_id), updated_at=now - timedelta(minutes=2),
        ),
        Telemetry(
            device_id=agent_id, timestamp=now - timedelta(minutes=1), cpu_usage=12.5,
            ram_usage=42.0, ip_local="10.0.0.4",
        ),
    ])
    await db_session.commit()

    result = await query_timeline(db_session, hours=1, limit=50)

    assert {item["source"] for item in result["items"]} == set(SOURCE_NAMES)
    times = [item["time"] for item in result["items"]]
    assert times == sorted(times, reverse=True)
    deception = next(item for item in result["items"] if item["source"] == "deception")
    assert "context=lab" in deception["detail"]
    assert deception["link"]["page"] == "kraken"


@pytest.mark.asyncio
async def test_timeline_source_filter_excludes_other_tables(db_session):
    now = datetime.now(timezone.utc)
    db_session.add(SiemEvent(
        time=now, source="firewall", source_type="firewall", event_id="only-siem",
        severity="LOW", message="only siem event",
    ))
    await db_session.commit()

    result = await query_timeline(db_session, hours=1, limit=10, sources="siem")

    assert result["selected_sources"] == ["siem"]
    assert [item["source"] for item in result["items"]] == ["siem"]
