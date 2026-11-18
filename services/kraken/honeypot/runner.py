import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from loguru import logger
from honeypot.sensors.ssh_sensor import SSHSensor
from honeypot.sensors.http_sensor import HTTPSensor
from honeypot.sensors.ftp_sensor import FTPSensor
from honeypot.sensors.telnet_sensor import TelnetSensor
from honeypot.sensors.smb_sensor import SMBSensor
from honeypot.sensors.rdp_sensor import RDPSensor


HEALTH_HOST = "127.0.0.1"
HEALTH_PORT = int(os.getenv("SENSOR_HEALTH_PORT", "8000"))


async def _health_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Risponde al healthcheck Docker senza toccare le porte esca.

    Il check non deve aprire connessioni verso SSH/HTTP/FTP ecc.: ogni
    connessione a un sensore viene registrata come attacco e riempirebbe il
    SIEM di eventi finti.  Questo listener parla solo con localhost.
    """
    try:
        await asyncio.wait_for(reader.read(1024), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError):
        pass
    try:
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n\r\n"
            b"ok"
        )
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _serve_health() -> None:
    server = await asyncio.start_server(_health_handler, HEALTH_HOST, HEALTH_PORT)
    logger.info(f"[Health] Listening on {HEALTH_HOST}:{HEALTH_PORT}")
    async with server:
        await server.serve_forever()


async def main():
    logger.info("🦑 Kraken Sensors starting up...")
    # One failed listener (for example a privileged port already in use) must
    # not silence every other protocol. Each task is supervised independently.
    sensors = [
        SSHSensor().start(),
        HTTPSensor().start(),
        FTPSensor().start(),
        TelnetSensor().start(),
        SMBSensor().start(),
        RDPSensor().start(),
    ]
    results = await asyncio.gather(
        _serve_health(), *sensors, return_exceptions=True
    )
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Sensor listener stopped: {result}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Sensors stopped.")
