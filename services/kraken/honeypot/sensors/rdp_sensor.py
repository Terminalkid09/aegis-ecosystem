"""RDP deception listener: records negotiation attempts and presents a banner."""
from __future__ import annotations

import asyncio
import uuid

from loguru import logger

from app.core.config import settings
from app.core.metrics import record_sensor_connection
from honeypot.sensors.ssh_sensor import _post_ingest

# Minimal X.224 Connection Confirm advertising an RDP server. It is a banner,
# not an authentication endpoint: no credentials are accepted.
_X224_CONFIRM = bytes.fromhex("030000130ed0000012340002010800000000000000")


class RDPSensor:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):
        self.host = host
        self.port = port or settings.RDP_SENSOR_PORT

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        record_sensor_connection("rdp")
        logger.info(f"[RDP] {ip}:{port} — session {session_id}")
        try:
            await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.write(_X224_CONFIRM)
            await writer.drain()
            # Keep the socket briefly so port scanners see a real RDP banner;
            # never parse or replay authentication material.
            await asyncio.sleep(0.2)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await _post_ingest({
                "sensor_type": "rdp",
                "attacker_ip": ip,
                "attacker_port": port,
                "sensor_port": self.port,
                "session_id": session_id,
                "commands": ["RDP negotiation (banner only; no authentication relay)"],
            })

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[RDP Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
