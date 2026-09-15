"""Listener syslog UDP + TCP.

Perché esiste: la maggior parte di firewall, switch, NAS e appliance sa
inviare **solo** syslog. Un SIEM che accetta solo HTTP costringe l'utente a
installare un relay. Con questo listener si punta il dispositivo direttamente
sulla piattaforma.

Robustezza:
- coda limitata (`MAX_QUEUE`): se il produttore è più veloce del consumatore i
  datagrammi eccedenti vengono **contati e scartati**, mai accumulati in
  memoria fino a uccidere il processo (un syslog storm non deve abbattere il
  brain);
- un errore di ingestione su un messaggio non ferma il listener;
- default **disabilitato**: nessuna porta in ascolto senza una scelta esplicita.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_QUEUE = 20000
MAX_DATAGRAM = 64 * 1024
# Batch di ingestione: si accorpano i messaggi arrivati insieme in una sola
# transazione (meno commit, meno pressione sul DB) senza aggiungere latenza
# percepibile.
BATCH_SIZE = 200
BATCH_WINDOW_S = 1.0


class SyslogListener:
    """Server UDP e TCP che normalizza i messaggi verso la pipeline SIEM."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None,
                 source_name: str = "syslog",
                 with_tcp: Optional[bool] = None) -> None:
        self.host = host or settings.SYSLOG_BIND
        self.port = int(port or settings.SYSLOG_PORT)
        self.source_name = source_name
        self.with_tcp = settings.SYSLOG_TCP_ENABLED if with_tcp is None else with_tcp
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE)
        self.stats: Dict[str, Any] = {
            "received": 0, "dropped": 0, "ingested": 0, "stored": 0,
            "alerts": 0, "errors": 0,
        }
        self._transports: List[Any] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: List[asyncio.Task] = []
        self._running = False

    # ── ciclo di vita ───────────────────────────────────────────────────────
    async def start(self) -> None:
        if self._running:
            return
        loop = asyncio.get_running_loop()
        try:
            udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self), local_addr=(self.host, self.port))
            self._transports.append(udp_transport)
        except OSError as exc:
            logger.error(f"Syslog UDP non avviato su {self.host}:{self.port}: {exc}")
            return
        if self.with_tcp:
            try:
                self._server = await asyncio.start_server(
                    self._handle_tcp, self.host, self.port)
            except OSError as exc:
                logger.warning(f"Syslog TCP non avviato su {self.host}:{self.port}: {exc}")
        self._running = True
        consumer = asyncio.create_task(self._consumer())
        # Un task in background che muore non deve restare invisibile: senza
        # questo callback un errore nel consumer si traduce in "nessun evento
        # arrivato, nessun log", che è il guasto più difficile da diagnosticare.
        consumer.add_done_callback(self._consumer_done)
        self._tasks.append(consumer)
        logger.info(f"Syslog listener attivo su {self.host}:{self.port} "
                    f"(udp{'+tcp' if self._server else ''})")

    def _consumer_done(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self.stats["errors"] += 1
            self._running = False
            logger.error(f"Consumer syslog terminato con errore: {exc!r}")

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        for transport in self._transports:
            with contextlib.suppress(Exception):
                transport.close()
        self._transports.clear()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        logger.info("Syslog listener fermato")

    # ── ingresso messaggi ───────────────────────────────────────────────────
    def offer(self, line: str, peer: Tuple[str, int] | None = None) -> None:
        """Accoda un messaggio. Se la coda è piena lo scarta contandolo."""
        self.stats["received"] += 1
        try:
            self.queue.put_nowait((line, peer))
        except asyncio.QueueFull:
            self.stats["dropped"] += 1

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") if writer else None
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                self.offer(line.decode("utf-8", errors="ignore").rstrip("\r\n"), peer)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _consumer(self) -> None:
        """Consuma la coda a batch e alimenta la pipeline SIEM."""
        from app.database.connection import AsyncSessionLocal
        from app.services.siem_pipeline import ingest_payload

        batch: List[str] = []
        while self._running or not self.queue.empty():
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=BATCH_WINDOW_S)
                batch.append(item[0])
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return
            while len(batch) < BATCH_SIZE and not self.queue.empty():
                batch.append(self.queue.get_nowait()[0])
            if not batch:
                continue
            payload = "\n".join(batch)
            batch = []
            try:
                async with AsyncSessionLocal() as db:
                    result = await ingest_payload(
                        db, self.source_name, payload,
                        meta={"source_type": "syslog", "received_at": None},
                        parser="syslog")
                self.stats["ingested"] += result.get("accepted", 0)
                self.stats["stored"] += result.get("stored", 0)
                self.stats["alerts"] += result.get("alerts", 0)
                if result.get("errors"):
                    self.stats["errors"] += 1
            except Exception as exc:
                self.stats["errors"] += 1
                logger.warning(f"Ingestione syslog fallita: {exc}")

    def health(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "bind": f"{self.host}:{self.port}",
            "tcp": self._server is not None,
            "queue_depth": self.queue.qsize(),
            "queue_capacity": MAX_QUEUE,
            **self.stats,
        }


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: SyslogListener) -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr) -> None:
        text = data[:MAX_DATAGRAM].decode("utf-8", errors="ignore").rstrip("\r\n")
        if text:
            self.listener.offer(text, addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        logger.debug(f"Syslog UDP error: {exc}")


_listener: Optional[SyslogListener] = None


def get_listener() -> Optional[SyslogListener]:
    return _listener


async def start_syslog_listener() -> Optional[SyslogListener]:
    """Avvia il listener se abilitato dalla configurazione."""
    global _listener
    if not settings.SYSLOG_ENABLED:
        logger.info("Syslog listener disabilitato (SYSLOG_ENABLED=false)")
        return None
    if _listener is None:
        _listener = SyslogListener()
    await _listener.start()
    return _listener


async def stop_syslog_listener() -> None:
    global _listener
    if _listener is not None:
        await _listener.stop()
        _listener = None
