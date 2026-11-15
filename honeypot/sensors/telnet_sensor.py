import asyncio
import uuid
from loguru import logger
from app.core.config import settings
from honeypot.sensors.ssh_sensor import (
    _post_ingest, _sandbox_create, _sandbox_exec, _sandbox_destroy,
)


class TelnetSensor:
    def __init__(self, host: str = "0.0.0.0", port: int = None):
        self.host = host
        self.port = port or settings.TELNET_SENSOR_PORT

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        attacker_ip, attacker_port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[Telnet] {attacker_ip}:{attacker_port} — session {session_id}")

        username = password = None
        commands = []
        sandbox = None

        try:
            writer.write(b"Ubuntu 22.04.3 LTS\r\nlocalhost login: ")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=8.0)
            raw_user = line.decode(errors="ignore").strip()
            username = raw_user.replace('\xff', '')[:128]

            writer.write(b"Password: ")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=8.0)
            password = line.decode(errors="ignore").strip().replace('\xff', '')[:256]

            writer.write(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n")
            await writer.drain()

            sandbox = await _sandbox_create(session_id)

            while True:
                writer.write(b"root@ubuntu:~# ")
                await writer.drain()

                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip().replace('\xff', '')
                if not cmd:
                    continue
                if len(commands) < 200:
                    commands.append(cmd)

                if cmd in ("exit", "logout", "quit"):
                    break

                if sandbox:
                    output = await _sandbox_exec(session_id, cmd)
                    if output:
                        out_str = output.replace('\n', '\r\n')
                        writer.write(out_str.encode('utf-8'))
                        if not out_str.endswith('\r\n'):
                            writer.write(b"\r\n")
                    else:
                        writer.write(f"bash: {cmd}: command not found\r\n".encode())
                else:
                    writer.write(f"bash: {cmd}: command not found\r\n".encode())
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            if sandbox:
                await _sandbox_destroy(session_id)

            await _post_ingest({
                "sensor_type": "telnet", "attacker_ip": attacker_ip,
                "attacker_port": attacker_port, "sensor_port": self.port,
                "session_id": session_id, "username": username,
                "password": password, "commands": commands,
            })

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[Telnet Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
