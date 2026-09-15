"""Listener syslog end-to-end su database reale.

Verifica il percorso che un firewall/NAS/switch percorre davvero: un datagramma
UDP (e una riga TCP) arrivano sulla porta del listener, vengono normalizzati e
finiscono nello store eventi. È il test che giustifica la frase "un apparato
può puntare direttamente sulla piattaforma": senza di esso il listener è solo
codice non esercitato.

Il consumer del listener apre una **sessione propria**
(`AsyncSessionLocal`), quindi gli eventi sono committati sul database di
test e non nella transazione dei fixture: la verifica rilegge con una sessione
nuova, esattamente come farebbe la dashboard.

Nota ambiente: il listener usa l'engine dell'applicazione, quindi oltre a
`TEST_DATABASE_URL` serve che anche `DATABASE_URL` punti a un database
raggiungibile (in CI/docker-compose lo è già).
"""
import asyncio
import socket
import uuid

from sqlalchemy import delete, func, select

from app.database.connection import AsyncSessionLocal
from app.database.models import Agent, Alert, LogSource, SiemEvent
from app.services.siem_pipeline import LOGS_SOURCE_AGENT_TYPE
from app.services.syslog_server import SyslogListener


def _source(prefix: str) -> str:
    """Nome sorgente univoco: la dedup per contenuto sopravvive ai test."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _wait_for_events(source: str, expected: int, timeout: float = 25.0) -> int:
    """Attende che gli eventi compaiano: il consumer lavora a batch."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    count = 0
    while loop.time() < deadline:
        async with AsyncSessionLocal() as db:
            count = int(await db.scalar(
                select(func.count(SiemEvent.id)).where(SiemEvent.source == source)) or 0)
        if count >= expected:
            return count
        await asyncio.sleep(0.5)
    return count


async def _cleanup(source: str) -> None:
    """Rimuove ciò che il listener ha committato per questa sorgente.

    Il listener scrive con una sessione propria (fuori dalla transazione dei
    fixture): senza pulizia le righe restano e i test che assumono tabelle
    vuote (es. telemetry) falliscono per un ordine di esecuzione diverso.

    Ogni sorgente di log è rappresentata da una riga sintetica in `agents`
    (così alert, incidenti e playbook funzionano senza duplicare la macchina
    del SOC): gli alert puntano al suo UUID, non al nome della sorgente.
    """
    async with AsyncSessionLocal() as db:
        agent = (await db.execute(select(Agent).where(
            Agent.hostname == source,
            Agent.agent_type == LOGS_SOURCE_AGENT_TYPE))).scalars().first()
        if agent is not None:
            await db.execute(delete(Alert).where(Alert.agent_id == agent.agent_id))
            await db.execute(delete(Agent).where(Agent.agent_id == agent.agent_id))
        await db.execute(delete(SiemEvent).where(SiemEvent.source == source))
        await db.execute(delete(LogSource).where(LogSource.name == source))
        await db.commit()


async def _wait_for_stat(listener: SyslogListener, key: str, expected: int,
                        timeout: float = 25.0) -> int:
    """Attende il contatore del listener.

    L'evento è visibile nello store prima che il consumer aggiorni i propri
    contatori (commit dentro ingest_payload, stats subito dopo): attendere il
    contatore evita di leggere un valore intermedio per una race del test.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if listener.stats.get(key, 0) >= expected:
            return listener.stats[key]
        await asyncio.sleep(0.25)
    return listener.stats.get(key, 0)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def test_udp_datagram_is_ingested_and_stored():
    source = _source("syslog-udp")
    port = _free_udp_port()
    listener = SyslogListener(host="127.0.0.1", port=port, source_name=source,
                              with_tcp=False)
    await listener.start()
    try:
        line = (f"<134>1 2026-09-15T12:00:01Z web-01 sshd 2201 ID47 - "
                f"Failed password for invalid user admin from 203.0.113.{uuid.uuid4().int % 200 + 11} "
                f"port 51234 ssh2")
        # Un vero datagramma UDP, non una chiamata diretta a offer().
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port))
        try:
            transport.sendto(line.encode("utf-8"))
        finally:
            transport.close()

        stored = await _wait_for_events(source, expected=1)
        assert stored >= 1, "il datagramma UDP non è arrivato nello store"
        assert await _wait_for_stat(listener, "stored", 1) >= 1, \
            "il listener non ha contato l'evento come ingerito"
        assert listener.stats["received"] >= 1

        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(SiemEvent).where(SiemEvent.source == source))).scalars().all()
        event = rows[0]
        assert event.source_type == "syslog"
        # I campi normalizzati, non solo il testo grezzo.
        assert event.hostname in ("web-01", None)
        assert event.src_ip == line.split("from ")[1].split(" ")[0]
    finally:
        await listener.stop()
        await _cleanup(source)


async def test_tcp_line_is_ingested_and_stored():
    source = _source("syslog-tcp")
    port = _free_udp_port()
    listener = SyslogListener(host="127.0.0.1", port=port, source_name=source,
                              with_tcp=True)
    await listener.start()
    try:
        assert listener._server is not None, "TCP non è in ascolto"
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            ip = f"198.51.100.{uuid.uuid4().int % 200 + 11}"
            # RFC 5424 completo: <PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG.
            # Senza il MSGID il campo structured-data assorbe il testo e la
            # riga è invalida — il parser la rifiuterebbe correttamente.
            writer.write((f"<134>1 2026-09-15T12:00:02Z db-01 sshd 3301 ID48 - "
                          f"Failed password for root from {ip} port 40022 ssh2\r\n").encode())
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            reader.feed_eof()

        stored = await _wait_for_events(source, expected=1)
        assert stored >= 1, "la riga TCP non è arrivata nello store"
        assert await _wait_for_stat(listener, "stored", 1) >= 1
    finally:
        await listener.stop()
        await _cleanup(source)


async def test_listener_health_is_exposed_while_running():
    listener = SyslogListener(host="127.0.0.1", port=_free_udp_port(),
                              source_name=_source("syslog-health"), with_tcp=True)
    await listener.start()
    try:
        health = listener.health()
        assert health["running"] is True
        assert health["tcp"] is True
        assert health["bind"].startswith("127.0.0.1:")
    finally:
        await listener.stop()
    assert listener.health()["running"] is False
