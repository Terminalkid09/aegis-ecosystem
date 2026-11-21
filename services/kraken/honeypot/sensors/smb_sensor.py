"""SMB deception listener and NetNTLMv2 capture.

The listener never proxies or relays SMB. It answers enough of the SMB2
negotiation to make an unauthenticated client offer NTLMSSP, then parses the
type-3 message. Only the challenge response is kept; no plaintext password is
ever present on an SMB login.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import uuid
from typing import Optional

from loguru import logger

from app.core.config import settings
from app.core.metrics import record_sensor_connection
from honeypot.sensors.ssh_sensor import _post_ingest

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
    # NTLMSSP strings are UTF-16LE. A latin/utf-8 fallback keeps malformed
    # captures readable instead of dropping the entire attempt.
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
    # The string is the conventional NetNTLMv2 material an analyst can test
    # offline. It is not a password and is never exported to Aegis.
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
    target_info = b"\x00\x00\x00\x00"  # empty AV pair terminator
    flags = 0x00008201
    header_len = 56
    payload_offset = header_len
    # Target name then target info, each with its own offset.
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
    # NegTokenResp with responseToken [2] = NTLMSSP type 2.
    oid = bytes.fromhex("060a2b06010401823702020a")
    response = b"\xa3" + bytes([len(ntlm) + 2]) + b"\x04" + bytes([len(ntlm)]) + ntlm
    supported = b"\xa2" + bytes([len(oid) + 2]) + oid
    body = supported + response
    neg_token = b"\x30" + bytes([len(body)]) + body
    response_body = struct.pack("<HHHH", 9, 1, 72, len(neg_token))
    return _smb2_header(1, message_id) + response_body + neg_token


class SMBSensor:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):
        self.host = host
        self.port = port or settings.SMB_SENSOR_PORT
        self.challenge = b"KRAKEN!!"
        self.decoy_path = ""

    def _ensure_decoy(self) -> bytes:
        """Create a harmless, deterministic lure file; never executable."""
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

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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
            # The first packet is normally SMB2 NEGOTIATE. Reply with a
            # negotiate response; then wait for SESSION_SETUP.
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

    async def start(self):
        server = await asyncio.start_server(self.handle, self.host, self.port)
        logger.info(f"[SMB Sensor] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()
