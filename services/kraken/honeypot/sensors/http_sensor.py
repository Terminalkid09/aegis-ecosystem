import asyncio
import uuid
from loguru import logger
from app.core.config import settings
from honeypot.sensors.ssh_sensor import _post_ingest


class HTTPSensor:
    """
    Passive HTTP sensor.
    Logs every inbound HTTP probe and returns a generic 200 response.
    Never executes code or proxies requests.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = None):
        self.host = host
        self.port = port or settings.HTTP_SENSOR_PORT

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        attacker_ip, attacker_port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[HTTP] {attacker_ip}:{attacker_port} — session {session_id}")

        raw = ""
        try:
            raw = (await asyncio.wait_for(reader.read(4096), timeout=5.0)).decode(errors="ignore")
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        finally:
            try:
                writer.write(
                    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n"
                    b"Content-Type: text/html\r\nContent-Length: 45\r\n\r\n"
                    b"<html><body><h1>It works!</h1></body></html>"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        method, path = self._parse_request(raw)
        commands = [f"{method} {path}"] if method and path else []
        await self._report(session_id, attacker_ip, attacker_port, commands)

    def _parse_request(self, raw: str):
        method = path = None
        lines = raw.splitlines()
        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, path = parts[0][:16], parts[1][:512]
        return method, path

    async def _report(self, session_id, ip, port, commands):
        await _post_ingest({
            "sensor_type": "http", "attacker_ip": ip,
            "attacker_port": port, "sensor_port": self.port,
            "session_id": session_id, "commands": commands,
        })

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[HTTP Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
