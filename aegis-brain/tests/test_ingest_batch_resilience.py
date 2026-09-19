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


# ---------------------------------------------------------------------------
# Audit: un evento che il database non puo' scrivere non deve diventare un 500
# ---------------------------------------------------------------------------
#
# Misurato dal vivo: un batch contenente un NUL byte in un nome processo
# rispondeva 500, non 200 con `rejected=1`. La causa non era il NUL in sé ma
# l'error path dell'handler: il commit fallito scade gli oggetti ORM della
# sessione, quindi toccare `agent.agent_id` PRIMA del rollback eseguiva un
# lazy-load su una sessione che richiede rollback -> PendingRollbackError, e
# l'error path diventava esso stesso l'errore. Poiché l'outbox rigioca il batch
# respinto, un simile evento bloccava la telemetria dell'endpoint per sempre.


@pytest.mark.asyncio
async def test_nul_byte_event_is_not_fatal(
        client, agent_auth_headers, test_agent):
    """Il NUL si rimuove all'ingresso: nessun evento perso, nessun 500."""
    payload = [
        _event(str(test_agent.agent_id), pid=8001, process_name="sano.exe"),
        _event(str(test_agent.agent_id), pid=8002, process_name="robust\x00.exe",
               parent_process_name="explorer\x00.exe"),
        _event(str(test_agent.agent_id), pid=8003, process_name="dopo.exe"),
    ]
    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 3, "l'evento col NUL è accettato, ripulito"
    assert body["rejected"] == 0


@pytest.mark.asyncio
async def test_error_path_survives_a_failed_write(
        client, agent_auth_headers, test_agent, monkeypatch):
    """Un errore di scrittura REALE finisce in `rejected`, non in un 500.

    Riproduce il meccanismo esatto: un commit che fallisce a flush, come
    fallirebbe per un valore che il database rifiuta. Se in quel ramo si legge
    un attributo ORM prima del rollback, il test fallisce con 500 — che è
    quello che succedeva in esercizio.
    """
    from app.database.models import Alert
    from app.services import telemetry_service

    real = telemetry_service.process_telemetry
    calls = {"n": 0}

    async def flaky(db, agent_id, data):
        calls["n"] += 1
        if calls["n"] == 1:
            # `severity` è NOT NULL: il flush fallisce e la sessione resta in
            # stato "rollback necessario", con le istanze scadute.
            db.add(Alert(agent_id=agent_id, severity=None, process_name="x",
                         event_type="probe", description="probe"))
            await db.commit()
            return
        return await real(db, agent_id, data)

    monkeypatch.setattr(telemetry_service, "process_telemetry", flaky)

    payload = [_event(str(test_agent.agent_id), pid=8101),
               _event(str(test_agent.agent_id), pid=8102)]
    r = await client.post("/api/v1/telemetry/report/batch",
                          json=payload, headers=agent_auth_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rejected"] == 1, "l'evento che ha fallito è dichiarato"
    assert body["accepted"] == 1, \
        "dopo il rollback la sessione torna usabile: l'evento sano passa"
