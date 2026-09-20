"""Policy di rischio e muting post-resolve."""
import types
import pytest

from app.rules.rule_definitions import rule_suspicious_execution_path, stamp_result
from app.services.alert_policy import (
    should_skip_known_signed_app_path,
    should_skip_trusted_noisy_rule,
    triage_mute_fingerprint,
)


def _event(**kw):
    base = {
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "timestamp": "2026-09-20T10:00:00+00:00",
        "event_type": "PROCESS_CREATED",
        "process_name": "Code.exe",
        "process_path": r"C:\Users\vic\Downloads\VSCode\Code.exe",
        "signature": "authenticode-trusted",
        "publisher": "Microsoft Corporation",
    }
    base.update(kw)
    from app.api.schemas.common import EventSchema
    return EventSchema(**base)


def test_s004_trusted_keeps_low_confidence_after_stamp():
    ev = _event()
    r = rule_suspicious_execution_path(ev)
    assert r.triggered
    assert r.confidence == "low"
    assert r.severity == "LOW"
    stamp_result(rule_suspicious_execution_path, r)
    assert r.confidence == "low"
    assert should_skip_trusted_noisy_rule("AEGIS-S004", r, ev)


def test_s004_unsigned_still_actionable():
    ev = _event(signature="unsigned:hash-mismatch", publisher=None)
    r = rule_suspicious_execution_path(ev)
    stamp_result(rule_suspicious_execution_path, r)
    assert r.severity == "HIGH"
    assert not should_skip_trusted_noisy_rule("AEGIS-S004", r, ev)


def test_known_signed_app_code_from_downloads():
    ev = _event()
    assert should_skip_known_signed_app_path(ev, "AEGIS-S004")


def test_triage_fingerprint_stable():
    alert = types.SimpleNamespace(
        event_type="PROCESS_CREATED",
        process_name="Code.exe",
        mitre_technique_id="T1059",
        evidence={"rules": [{"id": "AEGIS-S004", "version": "1.0"}]},
    )
    a = triage_mute_fingerprint(alert)
    b = triage_mute_fingerprint(alert)
    assert a == b
    assert "AEGIS-S004" in a


@pytest.mark.asyncio
async def test_resolve_records_triage_mute(monkeypatch):
    from app.services import telemetry_service as ts
    from app.database.models import Alert
    import uuid

    stored = {}

    class FakeRedis:
        async def setex(self, key, ttl, val):
            stored[key] = ttl

        async def exists(self, key):
            return key in stored

        async def delete(self, key):
            stored.pop(key, None)

    monkeypatch.setattr(ts, "redis_client", FakeRedis())
    agent = uuid.uuid4()
    alert = Alert(
        agent_id=agent,
        severity="HIGH",
        process_name="Code.exe",
        event_type="PROCESS_CREATED",
        description="test",
        evidence={"rules": [{"id": "AEGIS-S004"}]},
    )
    ttl = await ts.record_triage_mute(agent, alert)
    assert ttl == ts.TRIAGE_MUTE_TTL
    assert await ts._muted_by_triage(agent, triage_mute_fingerprint(alert))


def test_triage_fingerprint_distinguishes_detector_and_metric():
    """Il muting deve essere MIRATO: risolvere un'anomalia di CPU non deve
    silenziare quelle di rete, e un rilevatore NodeTrace non deve coprire
    gli altri (prima il fingerprint cadeva su event_type+processo)."""
    import types

    def _mk(ev):
        return types.SimpleNamespace(
            event_type="statistical_anomaly", process_name="System",
            mitre_technique_id=None, evidence=ev,
        )

    cpu = triage_mute_fingerprint(_mk({"source": "anomaly-engine", "metric": "cpu_usage"}))
    net = triage_mute_fingerprint(_mk({"source": "anomaly-engine", "metric": "network_sent"}))
    assert cpu != net, "metriche diverse = rumori diversi: muting separato"

    beacon = triage_mute_fingerprint(_mk({
        "source": "nodetrace", "type": "HIGH_CONNECTION_COUNT_TO_IP", "ip": "1.2.3.4"}))
    assert "HIGH_CONNECTION_COUNT_TO_IP" in beacon, \
        "il rilevatore NodeTrace deve entrare nel fingerprint"
    assert beacon != cpu


def test_triage_mute_ttl_is_seven_days():
    """Il resolve silenzia per una settimana, non per sempre: un muting
    infinito nasconderebbe una regressione reale."""
    from app.services import telemetry_service as ts

    assert ts.TRIAGE_MUTE_TTL == 7 * 86400


@pytest.mark.asyncio
async def test_triage_mute_suppresses_redetection_only_for_same_pattern(monkeypatch):
    """Il resolve NON e' cosmetico: la STESSA detection non torna piu' per
    7 giorni, mentre un processo diverso continua a essere segnalato."""
    import uuid

    from app.services import telemetry_service as ts
    from app.database.models import Alert

    stored = {}

    class FakeRedis:
        async def setex(self, key, ttl, val):
            stored[key] = ttl

        async def exists(self, key):
            return key in stored

        async def delete(self, key):
            stored.pop(key, None)

    monkeypatch.setattr(ts, "redis_client", FakeRedis())
    agent = uuid.uuid4()

    def _mk(name):
        return Alert(
            agent_id=agent, severity="HIGH", process_name=name,
            event_type="PROCESS_CREATED", description="test",
            evidence={"rules": [{"id": "AEGIS-S004"}]},
        )

    await ts.record_triage_mute(agent, _mk("Code.exe"))

    assert await ts._skip_new_alert(agent, _mk("Code.exe")), \
        "stessa detection dopo il resolve: deve essere silenziata"
    assert not await ts._skip_new_alert(agent, _mk("evil.exe")), \
        "processo diverso: il muting non deve coprire altro rumore"


@pytest.mark.asyncio
async def test_reopen_clears_triage_mute(client, admin_auth_headers, db_session,
                                         test_agent, monkeypatch):
    """PATCH resolve -> lock + feedback; riapertura -> muting rimosso così
    la detection puo' tornare visibile (niente vicolo cieco nel triage)."""
    from app.database.models import Alert
    from app.services import telemetry_service as ts

    stored = {}

    class FakeRedis:
        async def setex(self, key, ttl, val):
            stored[key] = ttl

        async def exists(self, key):
            return key in stored

        async def delete(self, key):
            stored.pop(key, None)

    monkeypatch.setattr(ts, "redis_client", FakeRedis())

    alert = Alert(
        agent_id=test_agent.agent_id, severity="HIGH", process_name="Code.exe",
        event_type="PROCESS_CREATED", description="test s004",
        evidence={"rules": [{"id": "AEGIS-S004"}]},
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)

    from app.services.alert_policy import triage_mute_fingerprint

    r = await client.patch(f"/api/v1/telemetry/alerts/{alert.id}/resolve",
                           json={"resolved": True}, headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_resolved"] is True
    # I campi di feedback esistono SEMPRE (anche a 0 con Redis giu'): la UI
    # non deve mostrare "muted 0 days" per un errore di parsing.
    assert isinstance(body["triage_muted_seconds"], int)
    assert body["process_killed"] is False  # pid assente: nessun kill
    assert body["triage_muted_seconds"] == ts.TRIAGE_MUTE_TTL, \
        "resolve deve lasciare il muting attivo per la stessa detection"
    assert await ts._muted_by_triage(
        alert.agent_id, triage_mute_fingerprint(alert))

    r = await client.patch(f"/api/v1/telemetry/alerts/{alert.id}/resolve",
                           json={"resolved": False}, headers=admin_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_resolved"] is False
    assert body["triage_muted_seconds"] == 0
    assert not await ts._muted_by_triage(
        alert.agent_id, triage_mute_fingerprint(alert)), \
        "riapertura: il muting deve sparire, altrimenti detection invisibile"
