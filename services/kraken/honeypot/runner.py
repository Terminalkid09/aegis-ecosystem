import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from loguru import logger
from honeypot.sensors.ssh_sensor import SSHSensor
from honeypot.sensors.http_sensor import HTTPSensor
from honeypot.sensors.ftp_sensor import FTPSensor
from honeypot.sensors.telnet_sensor import TelnetSensor


async def main():
    logger.info("🦑 Kraken Sensors starting up...")
    await asyncio.gather(
        SSHSensor().start(),
        HTTPSensor().start(),
        FTPSensor().start(),
        TelnetSensor().start(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Sensors stopped.")
