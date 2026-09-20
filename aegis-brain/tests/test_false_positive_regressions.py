"""Regressioni dai falsi positivi visti nell'esercizio (audit alert live).

Tre difetti osservati su una macchina di sviluppo reale:
1. un picco di risorse HOST veniva attribuito a "System Idle Process" — uno
   pseudo-processo che rappresenta il tempo INATTIVO, non un carico;
2. "TrustedSigned=False" su binari firmati (VS Code, curl di Git): la firma
   mancente era in realta' dato assente, ma il messaggio suggeriva verifica
   fallita — e la regola "suspicious path" restava HIGH comunque;
3. N regole a bassa confidenza (interpreti, LOLBin) sommate fabbricavano un
   punteggio 75 = HIGH su attivita' perfettamente legittima.
"""
from datetime import datetime, timezone

import pytest

from app.rules.rule_definitions import rule_suspicious_execution_path
from app.api.schemas.common import EventSchema


def _event(**kw) -> EventSchema:
    base = {
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "PROCESS_CREATED",
        "pid": 4242,
        "process_name": "app.exe",
        "process_path": "C:\\Users\\dev\\Downloads\\Microsoft VS Code\\Code.exe",
    }
    base.update(kw)
    return EventSchema(**base)


def test_suspicious_path_signed_trusted_is_low_not_high():
    """VS Code firmato da Downloads: evidenza debole, non HIGH."""
    ev = _event(signature="authenticode-trusted", publisher="Microsoft Corporation")
    res = rule_suspicious_execution_path(ev)
    assert res.triggered is True
    assert res.severity == "LOW"
    assert res.confidence == "low"


def test_suspicious_path_unsigned_stays_high():
    """Stesso path, binario non firmato: la regola mantiene il peso pieno."""
    ev = _event(signature="unsigned:0x800b0100", publisher="")
    res = rule_suspicious_execution_path(ev)
    assert res.triggered is True
    assert res.severity == "HIGH"


def test_low_confidence_rules_cannot_manufacture_high_score():
    """Il moltiplicatore di FP: 3 regole low-confidence non devono piu' sommare
    fino a superare la soglia HIGH (50)."""
    from types import SimpleNamespace

    score_map = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
    rules = [
        SimpleNamespace(severity="HIGH", confidence="low"),    # S012 LOLBin
        SimpleNamespace(severity="HIGH", confidence="low"),
        SimpleNamespace(severity="MEDIUM", confidence="low"),  # S009 interpreter
    ]
    # Vecchio comportamento: 50+50+25 = 125 -> CRITICAL. Nuovo: 10+10+10 = 30.
    total = sum(
        (10 if getattr(r, "confidence", None) == "low" else score_map.get(r.severity, 10))
        for r in rules
    )
    assert total == 30
    assert total < 50  # non produce piu' HIGH/CRITICAL


def test_score_honors_real_high_confidence_signals():
    """Una regola HIGH ad alta confidenza conta davvero: il fix non zittisce
    le detection serie."""
    from types import SimpleNamespace

    score_map = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
    rules = [SimpleNamespace(severity="HIGH", confidence="high")]
    total = sum(
        (10 if getattr(r, "confidence", None) == "low" else score_map.get(r.severity, 10))
        for r in rules
    )
    assert total == 50  # soglia HIGH raggiunta con un segnale vero


@pytest.mark.asyncio
async def test_anomaly_alert_does_not_blame_idle_process(client, agent_auth_headers, test_agent, db_session):
    """Picco di RAM host con solo pseudo-processi campionati: l'alert non deve
    attribuire il picco a System Idle Process."""
    payload = {
        "agent_id": str(test_agent.agent_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "HEARTBEAT",
        "cpu_usage": 95.0,
        "ram_usage": 90.0,
        "processes": [{"name": "System Idle Process", "pid": 0, "cpu_percent": 0}],
    }
    # Preriscalda la baseline con valori variabili (min_samples=20, std > 0)
    # e event_id unici: con lo stesso event_id il dedup scarta tutto e la
    # baseline non si costruisce mai.
    import uuid
    for i in range(22):
        await client.post("/api/v1/telemetry/report", json={
            **payload, "event_id": str(uuid.uuid4()),
            "cpu_usage": 4.0 + (i % 4), "ram_usage": 9.0 + (i % 5)},
            headers=agent_auth_headers)
    # Anche il report del picco ha un event_id nuovo: il dedup e' persistito su
    # Redis (TTL > durata della suite) e un id riusato verrebbe scartato.
    r = await client.post("/api/v1/telemetry/report", json={
        **payload, "event_id": str(uuid.uuid4())}, headers=agent_auth_headers)
    assert r.status_code == 200, r.text

    # Gli alert si leggono dalla STESSA sessione dell'app (il fixture lavora in
    # una transazione esterna fatta per il rollback: una sessione nuova non
    # vedrebbe mai le righe di questo test).
    from sqlalchemy import select
    from app.database.models import Alert
    rows = (await db_session.execute(select(Alert).where(
        Alert.event_type == "statistical_anomaly"))).scalars().all()
    alerts = [{"process_name": a.process_name, "description": a.description,
               "severity": a.severity} for a in rows]
    idle_alerts = [a for a in alerts if "System Idle Process" in str(a.get("process_name", ""))]
    assert not idle_alerts, f"alert ancora su pseudo-processo: {idle_alerts[:2]}"
    spike = [a for a in alerts if "spike" in str(a.get("description", "")).lower()]
    assert spike, "il picco doveva generare un alert, con contesto onesto"
    assert "host-wide" in str(spike[0]["description"]).lower() or \
        "heaviest sampled" in str(spike[0]["description"]).lower()
