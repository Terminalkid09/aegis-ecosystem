import asyncio
import uuid
import os
import hashlib
from loguru import logger
from app.core.config import settings
from honeypot.sensors.ssh_sensor import _post_ingest
from app.services.siem import siem_logger

class FTPSensor:
    def __init__(self, host: str = "0.0.0.0", port: int = None):
        self.host = host
        self.port = port or settings.FTP_SENSOR_PORT
        self.pasv_server = None

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        attacker_ip, attacker_port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        logger.info(f"[FTP] {attacker_ip}:{attacker_port} — session {session_id}")

        username = password = None
        commands = []
        
        async def pasv_handler(d_reader, d_writer):
            malware_dir = settings.MALWARE_DIR
            os.makedirs(malware_dir, exist_ok=True)
            content = await d_reader.read()
            if content:
                sha256 = hashlib.sha256(content).hexdigest()
                filename = "ftp_upload.bin"
                save_path = os.path.join(malware_dir, f"{sha256}_{filename}")
                with open(save_path, "wb") as f:
                    f.write(content)
                siem_logger.log_malware({
                    "session_id": session_id,
                    "filename": filename,
                    "sha256": sha256,
                    "size": len(content),
                    "path": save_path
                })
            d_writer.close()

        try:
            writer.write(b"220 FTP server ready.\r\n")
            await writer.drain()

            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip()
                if not cmd:
                    continue
                commands.append(cmd[:256])
                upper = cmd.upper()

                if upper.startswith("USER "):
                    username = cmd[5:].strip()[:128]
                    writer.write(b"331 Password required.\r\n")
                elif upper.startswith("PASS "):
                    password = cmd[5:].strip()[:256]
                    writer.write(b"230 Login successful.\r\n")
                elif upper.startswith("SYST"):
                    writer.write(b"215 UNIX Type: L8\r\n")
                elif upper.startswith("FEAT"):
                    writer.write(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
                elif upper.startswith("PWD"):
                    writer.write(b"257 \"/\" is the current directory\r\n")
                elif upper.startswith("TYPE"):
                    writer.write(b"200 Type set to I\r\n")
                elif upper.startswith("PASV"):
                    self.pasv_server = await asyncio.start_server(pasv_handler, '0.0.0.0', 0)
                    port = self.pasv_server.sockets[0].getsockname()[1]
                    p1, p2 = divmod(port, 256)
                    # Local IP for demo, in prod this should be external IP
                    writer.write(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2}).\r\n".encode())
                elif upper.startswith("STOR "):
                    writer.write(b"150 Ok to send data.\r\n")
                    await writer.drain()
                    await asyncio.sleep(2)
                    writer.write(b"226 Transfer complete.\r\n")
                elif upper.startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    break
                else:
                    writer.write(b"500 Unknown command.\r\n")
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if self.pasv_server:
                self.pasv_server.close()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        await _post_ingest({
            "sensor_type": "ftp", "attacker_ip": attacker_ip,
            "attacker_port": attacker_port, "sensor_port": self.port,
            "session_id": session_id, "username": username,
            "password": password, "commands": commands,
        })

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[FTP Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
