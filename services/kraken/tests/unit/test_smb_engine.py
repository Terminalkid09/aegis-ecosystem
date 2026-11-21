import asyncio
import socket

import pytest

pytest.importorskip("impacket")

from impacket.smbconnection import SMBConnection

from app.core.config import settings
from honeypot.sensors import smb_sensor
from honeypot.sensors.smb_sensor import SMBSensor


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.mark.asyncio
async def test_real_smb2_share_lists_files_and_captures_ntlm(monkeypatch):
    events = []

    async def fake_ingest(payload):
        events.append(payload)

    monkeypatch.setattr(smb_sensor, "_post_ingest", fake_ingest)
    sensor = SMBSensor(host="127.0.0.1", port=_free_port())
    task = asyncio.create_task(sensor.start())
    await asyncio.wait_for(sensor.ready.wait(), timeout=5)
    await asyncio.sleep(0.4)

    def client():
        conn = SMBConnection(
            remoteName="127.0.0.1",
            remoteHost="127.0.0.1",
            sess_port=sensor.port,
            timeout=5,
        )
        conn.login("alice", "s3cret")
        names = [entry.get_longname() for entry in conn.listPath(settings.SMB_SHARE_NAME, "*")]
        conn.logoff()
        conn.close()
        return names

    names = await asyncio.to_thread(client)
    assert "README.txt" in names

    for _ in range(50):
        if events:
            break
        await asyncio.sleep(0.1)
    assert events
    event = events[0]
    assert event["sensor_type"] == "smb"
    assert event["username"] == "alice"
    assert event["ntlm_hash"]
    assert "::" in event["ntlm_hash"]

    sensor.stop()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
