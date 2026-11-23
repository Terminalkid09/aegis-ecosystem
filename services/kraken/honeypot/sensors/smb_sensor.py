"""SMB2 honeypot with a real share engine and NetNTLMv2 capture.

The default engine is Impacket's SMB server: clients can negotiate SMB2,
authenticate, list the ``Finance$`` share and read/write decoy files.  The
engine logs the NTLMv2 material from the same session, so a successful login
is still useful for detection even when the client never sends a plaintext
password.

``SMB_SENSOR_ENGINE=raw`` keeps the old negotiation-only listener as a
fallback for minimal deployments and for the protocol parser tests.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import threading
import uuid
from pathlib import Path
from typing import Optional

from loguru import logger

from app.core.config import settings
from app.core.metrics import record_sensor_connection
from honeypot.sensors.ssh_sensor import _post_ingest

try:  # pragma: no cover - exercised by the integration test when installed
    from impacket.smbserver import SimpleSMBServer, outputToJohnFormat
except ImportError:  # pragma: no cover
    SimpleSMBServer = None
    outputToJohnFormat = None

NTLMSSP = b"NTLMSSP\x00"


def _find_message(data: bytes, message_type: int) -> int:
    marker = NTLMSSP + bytes([message_type, 0, 0, 0])
    return data.find(marker)


def _field(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        return 0, 0
    length, _maximum, relative = struct.unpack_from("<HHI", data, offset)
    return length, relative


def _payload(data: bytes, base: int, offset: int, length: int) -> bytes:
    start = base + offset
    if start < base or start + length > len(data):
        return b""
    return data[start:start + length]


def parse_ntlm_type3(data: bytes, challenge: bytes | None = None) -> Optional[dict]:
    """Extract user/domain/NetNTLMv2 response from an NTLMSSP type-3 message."""
    base = _find_message(data, 3)
    if base < 0:
        return None
    nt_len, nt_off = _field(data, base + 20)
    domain_len, domain_off = _field(data, base + 28)
    user_len, user_off = _field(data, base + 36)
    if not nt_len:
        return None

    def _text(raw: bytes) -> str:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return raw.decode("utf-8", "replace")

    domain = _text(_payload(data, base, domain_off, domain_len))
    username = _text(_payload(data, base, user_off, user_len))
    response = _payload(data, base, nt_off, nt_len)
    if not response:
        return None
    challenge_hex = (challenge or b"\x00" * 8).hex()
    ntlm_hash = f"{username}::{domain}:{challenge_hex}:{response.hex()}"
    return {
        "username": username[:128],
        "domain": domain[:128],
        "ntlm_hash": ntlm_hash[:1024],
        "response": response,
    }


def _smb2_header(command: int, message_id: int = 0, status: int = 0) -> bytes:
    header = struct.pack(
        "<4sHHIHHIIQIIQ",
        b"\xfeSMB", 64, 1, status, command, 0, 1, 0,
        message_id, 0, 0, 0,
    )
    return header + b"\x00" * 16


def _negotiate_response(message_id: int = 0) -> bytes:
    body = struct.pack(
        "<HHHHIIIIQQHHI",
        65, 0x0202, 0, 0, 0,
        1024 * 1024, 1024 * 1024, 1024 * 1024,
        0, 0, 0, 0, 0,
    )
    return _smb2_header(0, message_id) + body


def _ntlm_type2(challenge: bytes) -> bytes:
    target = b"KRAKEN"
    target_name = target.decode("utf-16-le").encode("utf-16-le")
    target_info = b"\x00\x00\x00\x00"
    flags = 0x00008201
    header_len = 56
    payload_offset = header_len
    target_info_offset = payload_offset + len(target_name)
    head = (
        NTLMSSP + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target_name), len(target_name), payload_offset)
        + struct.pack("<I", flags)
        + challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), target_info_offset)
    )
    return head + target_name + target_info


def _session_setup_challenge(challenge: bytes, message_id: int = 1) -> bytes:
    ntlm = _ntlm_type2(challenge)
    oid = bytes.fromhex("060a2b06010401823702020a")
    response = b"\xa3" + bytes([len(ntlm) + 2]) + b"\x04" + bytes([len(ntlm)]) + ntlm
    supported = b"\xa2" + bytes([len(oid) + 2]) + oid
    body = supported + response
    neg_token = b"\x30" + bytes([len(body)]) + body
    response_body = struct.pack("<HHHH", 9, 1, 72, len(neg_token))
    return _smb2_header(1, message_id) + response_body + neg_token


def _share_root() -> Path:
    root = Path(settings.DATA_DIR) / "smb" / settings.SMB_SHARE_NAME
    root.mkdir(parents=True, exist_ok=True)
    decoys = {
        "README.txt": "Finance file server. Authorized users only.\n",
        "finance_q4.csv": "department,vendor,amount\nfinance,acme,1000\nfinance,globex,2500\n",
        "payroll_2024.xlsx": "employee,department,salary\n",
        "IT/backup-notes.txt": "Restore point: vault01.corp.local\\backups\n",
    }
    for relative, content in decoys.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    return root


class SMBSensor:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):
        self.host = host
        self.port = settings.SMB_SENSOR_PORT if port is None else port
        self.challenge = b"KRAKEN!!"
        self.decoy_path = ""
        self._server = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.ready = asyncio.Event()

    def _ensure_decoy(self) -> bytes:
        """Keep the legacy raw listener's deterministic lure file."""
        directory = os.path.join(settings.DATA_DIR, "decoy")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "finance_q4.csv")
        content = (b"department,vendor,amount\nfinance,acme,1000\n"
                   b"finance,globex,2500\n")
        if not os.path.exists(path):
            with open(path, "wb") as handle:
                handle.write(content)
        self.decoy_path = path
        return content

    async def _consume(self):
        assert self._queue is not None
        while True:
            payload = await self._queue.get()
            try:
                await _post_ingest(payload)
            finally:
                self._queue.task_done()

    def _enqueue(self, payload: dict) -> None:
        loop, queue = self._loop, self._queue
        if loop is not None and queue is not None and not loop.is_closed():
            loop.call_soon_threadsafe(queue.put_nowait, payload)

    def _auth_callback(self, smbServer, connData, domain_name, user_name, host_name):
        record_sensor_connection("smb")
        ip = connData.get("ClientIP") or "unknown"
        try:
            port = int(connData.get("ClientPort") or 0)
        except (TypeError, ValueError):
            port = 0
        ntlm_hash = None
        try:
            auth = connData["AUTHENTICATE_MESSAGE"]
            challenge = connData["CHALLENGE_MESSAGE"]["challenge"]
            data = outputToJohnFormat(
                challenge,
                auth["user_name"],
                auth["domain_name"],
                auth["lanman"],
                auth["ntlm"],
            )
            if data:
                ntlm_hash = data.get("hash_string")
        except Exception as exc:
            logger.debug(f"[SMB] NetNTLMv2 material unavailable: {exc}")

        self._enqueue({
            "sensor_type": "smb",
            "attacker_ip": ip,
            "attacker_port": port,
            "sensor_port": self.port,
            "session_id": str(uuid.uuid4()),
            "username": (user_name or "")[:128] or None,
            "domain": (domain_name or "")[:128] or None,
            "ntlm_hash": ntlm_hash[:1024] if ntlm_hash else None,
            "commands": [
                "SMB2 authentication",
                f"host={host_name or 'unknown'}",
                f"share={settings.SMB_SHARE_NAME}",
            ],
        })

    async def _start_impacket(self):
        root = _share_root()
        logs = Path(settings.DATA_DIR) / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        log_path = logs / "smb.log"
        self._server = SimpleSMBServer(
            listenAddress=self.host,
            listenPort=self.port,
        )
        config = self._server.getServer().getServerConfig()
        config.set("global", "server_name", settings.SMB_SERVER_NAME)
        config.set("global", "server_os", "Windows Server 2019 17763")
        config.set("global", "server_domain", "CORP")
        config.set("global", "challenge", self.challenge.hex())
        config.set("global", "log_file", str(log_path))
        self._server.getServer().processConfigFile()
        self._server.addShare(
            settings.SMB_SHARE_NAME, str(root), shareComment="Finance", readOnly="no"
        )
        self._server.setSMB2Support(True)
        self._server.setAuthCallback(self._auth_callback)
        self._thread = threading.Thread(
            target=self._serve_impacket, name="kraken-smb", daemon=True
        )
        self._thread.start()
        logger.info(
            f"[SMB Sensor] Listening on {self.host}:{self.port} "
            f"(SMB2, share={settings.SMB_SHARE_NAME})"
        )
        self.ready.set()
        consumer = asyncio.create_task(self._consume())
        try:
            await asyncio.Event().wait()
        finally:
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)
            self.stop()

    def _serve_impacket(self):
        try:
            self._server.start()
        except Exception as exc:
            logger.error(f"[SMB Sensor] engine stopped: {exc}")
            self.ready.set()

    def stop(self):
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    async def _handle_raw(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, port = peer[0], peer[1]
        session_id = str(uuid.uuid4())
        record_sensor_connection("smb")
        logger.info(f"[SMB] {ip}:{port} — session {session_id}")

        decoy = self._ensure_decoy()
        username = None
        ntlm_hash = None
        commands = [f"SMB negotiation; decoy=finance_q4.csv sha256={hashlib.sha256(decoy).hexdigest()}"]

        try:
            first = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if first:
                message_id = 0
                if len(first) >= 32:
                    message_id = struct.unpack_from("<Q", first, 4 + 24)[0]
                writer.write(_negotiate_response(message_id))
                await writer.drain()
                data = await asyncio.wait_for(reader.read(65536), timeout=10.0)
                if data:
                    parsed = parse_ntlm_type3(data, self.challenge)
                    if parsed:
                        username = parsed["username"]
                        ntlm_hash = parsed["ntlm_hash"]
                    writer.write(_session_setup_challenge(self.challenge, message_id + 1))
                    await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await _post_ingest({
                "sensor_type": "smb",
                "attacker_ip": ip,
                "attacker_port": port,
                "sensor_port": self.port,
                "session_id": session_id,
                "username": username,
                "ntlm_hash": ntlm_hash,
                "commands": commands,
            })

    async def _start_raw(self):
        logger.warning("[SMB Sensor] raw negotiation engine enabled; share interaction disabled")
        server = await asyncio.start_server(self._handle_raw, self.host, self.port)
        logger.info(f"[SMB Sensor] Listening on {self.host}:{self.port} (raw)")
        self.ready.set()
        async with server:
            await server.serve_forever()

    async def start(self):
        self._queue = asyncio.Queue(maxsize=1000)
        self._loop = asyncio.get_running_loop()
        if settings.SMB_SENSOR_ENGINE.lower() != "impacket" or SimpleSMBServer is None:
            await self._start_raw()
            return
        await self._start_impacket()
