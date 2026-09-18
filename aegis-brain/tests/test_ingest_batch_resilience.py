"""Resilienza dell'ingestion batch: un evento guasto non deve farne perdere 99.

Questi test nascono da un difetto reale osservato in esercizio: il container
brain rispondeva `422` a OGNI chiamata a `/api/v1/telemetry/report/batch`, lo
spool cifrato dell'agente cresceva e la telemetria del sensore non arrivava
mai. Causa: `payload: List[EventSchema]` fa convalidare la lista in blocco,
quindi UN evento fuori schema (una command line oltre 4096 caratteri — nel caso
reale l'agente NodeTrace che invocava curl con un JSON in argv) faceva
respingere l'intera richiesta, prima ancora di entrare nell'handler. E poiché
l'outbox rigioca il batch respinto partendo dalle righe più vecchie, quel
singolo evento restava in testa alla coda e bloccava tutto per sempre.

Da qui le due proprietà che questi test bloccano:

1. la validazione è per-evento, non per batch;
2. un campo stringa troppo lungo viene troncato e dichiarato, non rifiutato.
"""
from datetime import datetime, timezone

import pytest


def _event(agent_id: str, **overrides) -> dict:
    base = {
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "PROCESS_CREATED",
        "pid": 4242,
        "process_name": "notepad.exe",
        "process_path": "C:\\Windows\\System32\\notepad.exe",
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_batch_of_healthy_events_all_accepted(client, agent_auth_headers, test_agent):
    payload = [_event(str(test_agent.agent_id), pid=1000 + i) for i in range(5)]
    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 5
    assert body["rejected"] == 0


@pytest.mark.asyncio
async def test_one_invalid_event_does_not_reject_the_batch(
        client, agent_auth_headers, test_agent):
    """Il caso che in esercizio azzerava la telemetria.

    L'evento guasto è `seq: -1` (vincolo `ge=0`): non è troncatura, è proprio
    fuori schema, quindi resta un rifiuto — ma solo di quell'evento.
    """
    payload = [_event(str(test_agent.agent_id), pid=2000 + i) for i in range(4)]
    payload.insert(2, _event(str(test_agent.agent_id), pid=9999, seq=-1))

    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)

    # Il punto centrale: NON 422.
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 4, "i 4 eventi sani devono passare"
    assert body["rejected"] == 1, "solo l'evento fuori schema viene scartato"


@pytest.mark.asyncio
async def test_long_command_line_is_truncated_not_rejected(
        client, agent_auth_headers, test_agent):
    """Una command line da 12 KB non deve impedire l'ingestion.

    Era esattamente questo (misurato: 12000+ caratteri) a produrre il 422 che
    bloccava lo spool dell'agente.
    """
    huge = "x" * 12000
    payload = [_event(str(test_agent.agent_id), pid=3001, command_line=huge)]

    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)

    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 1


@pytest.mark.asyncio
async def test_event_for_another_agent_is_rejected_individually(
        client, agent_auth_headers, test_agent):
    """Evento firmato da un altro agente: scartato quello, non il batch."""
    payload = [
        _event(str(test_agent.agent_id), pid=4001),
        _event("00000000-0000-0000-0000-000000000000", pid=4002),
    ]
    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 1


@pytest.mark.asyncio
async def test_batch_over_100_is_rejected_loudly(client, agent_auth_headers, test_agent):
    payload = [_event(str(test_agent.agent_id), pid=5000 + i) for i in range(101)]
    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_single_report_with_long_command_line_still_works(
        client, agent_auth_headers, test_agent):
    """Il singolo `/report` ha la stessa validazione: anche lì si tronca.

    Senza questo, il fallback per-evento dell'outbox (usato quando il brain non
    supporta il batch) sarebbe stato rotto allo stesso modo.
    """
    r = await client.post("/api/v1/telemetry/report",
                          json=_event(str(test_agent.agent_id), pid=6001,
                                      command_line="y" * 9000),
                          headers=agent_auth_headers)
    assert r.status_code == 200, r.text
