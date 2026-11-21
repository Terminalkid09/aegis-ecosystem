import asyncio
import ftplib
import io

import pytest

from app.core.config import settings
from honeypot.sensors import ftp_sensor
from honeypot.sensors.ftp_sensor import FTPSensor


@pytest.mark.asyncio
async def test_real_ftp_engine_accepts_any_login_and_serves_decoys(monkeypatch):
    events = []

    async def fake_ingest(payload):
        events.append(payload)

    monkeypatch.setattr(ftp_sensor, "_post_ingest", fake_ingest)
    settings.FTP_PASV_MIN_PORT = 30200
    settings.FTP_PASV_MAX_PORT = 30220
    sensor = FTPSensor(host="127.0.0.1", port=0)
    task = asyncio.create_task(sensor.start())
    for _ in range(50):
        if sensor.bound_port:
            break
        await asyncio.sleep(0.1)
    assert sensor.bound_port

    def client():
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", sensor.bound_port, timeout=5)
        ftp.login("alice", "s3cret")
        assert ftp.pwd() == "/"
        assert "README.txt" in ftp.nlst()
        ftp.storbinary("STOR upload.txt", io.BytesIO(b"captured"))
        buf = io.BytesIO()
        ftp.retrbinary("RETR upload.txt", buf.write)
        assert buf.getvalue() == b"captured"
        ftp.quit()

    await asyncio.to_thread(client)
    for _ in range(50):
        if events:
            break
        await asyncio.sleep(0.1)

    assert events
    event = events[0]
    assert event["sensor_type"] == "ftp"
    assert event["username"] == "alice"
    assert event["password"] == "s3cret"
    assert any("STOR upload.txt" in command for command in event["commands"])

    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
