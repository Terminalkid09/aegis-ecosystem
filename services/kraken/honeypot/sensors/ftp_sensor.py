"""Real FTP engine for the Kraken honeypot.

`pyftpdlib` provides the protocol state machine, passive data channels and the
filesystem operations.  The authorizer deliberately accepts any credentials so
the attempt is captured, while the exposed filesystem is a disposable decoy
tree.  No host path outside ``FTP_ROOT`` is reachable.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import threading
import uuid
from pathlib import Path

from loguru import logger
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from app.core.config import settings
from app.services.siem import siem_logger
from honeypot.sensors.ssh_sensor import _post_ingest


def _root() -> Path:
    root = Path(settings.DATA_DIR) / "ftp_root"
    root.mkdir(parents=True, exist_ok=True)
    decoys = {
        "README.txt": "Acme file transfer service\nAuthorized users only.\n",
        "finance_q4.csv": "department,vendor,amount\nfinance,acme,1000\nfinance,globex,2500\n",
        "backup/notes.txt": "Nightly backup target: vault01.corp.local\n",
    }
    for relative, content in decoys.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    return root


class _AnyUserAuthorizer(DummyAuthorizer):
    def __init__(self, home: Path):
        self.home = str(home)

    def validate_authentication(self, username, password, handler):
        handler.kraken_username = username[:128]
        handler.kraken_password = password[:256]
        return True

    def has_user(self, username):
        return True

    def get_home_dir(self, username):
        return self.home

    def get_perms(self, username):
        return "elradfmwMT"

    def has_perm(self, username, perm, path=None):
        # The authorizer is intentionally credential-agnostic; every decoy
        # filesystem operation is allowed inside the isolated root.
        return True

    def get_msg_login(self, username):
        return "Login successful."

    def get_msg_quit(self, username):
        return "Goodbye."

    def impersonate_user(self, username, password):
        pass

    def terminate_impersonation(self, username):
        pass


class _KrakenFTPHandler(FTPHandler):
    banner = "220 (vsFTPd 3.0.5)"
    timeout = 300
    auth_failed_timeout = 5

    # Set by FTPSensor.start() before the thread accepts connections.
    ingest_loop: asyncio.AbstractEventLoop | None = None
    ingest_queue: asyncio.Queue | None = None

    def on_connect(self):
        self.kraken_session_id = str(uuid.uuid4())
        self.kraken_commands: list[str] = []
        self.kraken_username: str | None = None
        self.kraken_password: str | None = None

    def ftp_USER(self, line):
        self.kraken_username = line[:128]
        self.kraken_commands.append(f"USER {line[:128]}")
        super().ftp_USER(line)

    def ftp_PASS(self, line):
        self.kraken_password = line[:256]
        self.kraken_commands.append("PASS ***")
        super().ftp_PASS(line)

    def on_file_received(self, file):
        try:
            path = Path(file).resolve()
            if not str(path).startswith(str(Path(self.authorizer.home).resolve())):
                return
            size = path.stat().st_size
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            sha256 = digest.hexdigest()
            siem_logger.log_malware({
                "session_id": getattr(self, "kraken_session_id", "unknown"),
                "filename": path.name,
                "sha256": sha256,
                "size": size,
                "path": str(path),
            })
            self.kraken_commands.append(f"STOR {path.name} ({size} bytes, sha256={sha256})")
        except Exception as exc:
            logger.warning(f"[FTP] upload capture failed: {exc}")

    def on_disconnect(self):
        loop = type(self).ingest_loop
        queue = type(self).ingest_queue
        if loop is not None and queue is not None and not loop.is_closed():
            payload = {
                "sensor_type": "ftp",
                "attacker_ip": self.remote_ip,
                "attacker_port": self.remote_port,
                "sensor_port": settings.FTP_SENSOR_PORT,
                "session_id": getattr(self, "kraken_session_id", str(uuid.uuid4())),
                "username": getattr(self, "kraken_username", None),
                "password": getattr(self, "kraken_password", None),
                "commands": getattr(self, "kraken_commands", [])[:200],
            }
            loop.call_soon_threadsafe(queue.put_nowait, payload)
        super().on_disconnect()


class FTPSensor:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):
        self.host = host
        self.port = settings.FTP_SENSOR_PORT if port is None else port
        self._server: FTPServer | None = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue | None = None
        self.bound_port: int | None = None

    async def _consume(self):
        assert self._queue is not None
        while True:
            payload = await self._queue.get()
            try:
                await _post_ingest(payload)
            finally:
                self._queue.task_done()

    async def start(self):
        self._queue = asyncio.Queue(maxsize=1000)
        loop = asyncio.get_running_loop()
        _KrakenFTPHandler.ingest_loop = loop
        _KrakenFTPHandler.ingest_queue = self._queue

        authorizer = _AnyUserAuthorizer(_root())
        handler = type("KrakenFTPHandler", (_KrakenFTPHandler,), {
            "authorizer": authorizer,
            "passive_ports": range(settings.FTP_PASV_MIN_PORT, settings.FTP_PASV_MAX_PORT + 1),
            "masquerade_address": settings.FTP_PASV_ADVERTISE_HOST or None,
            "permit_foreign_addresses": True,
            "use_sendfile": False,
        })
        self._server = FTPServer((self.host, self.port), handler)
        sock = self._server.socket
        self.bound_port = sock.getsockname()[1]
        self._thread = threading.Thread(
            target=self._serve,
            name="kraken-ftp",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"[FTP Sensor] Listening on {self.host}:{self.bound_port} (pyftpdlib)")
        consumer = asyncio.create_task(self._consume())
        try:
            await asyncio.Event().wait()
        finally:
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)
            if self._server is not None:
                self._server.close_all()
            if self._thread is not None:
                self._thread.join(timeout=3)

    def _serve(self):
        try:
            self._server.serve_forever(timeout=0.5, blocking=True, handle_exit=False)
        except Exception as exc:
            logger.error(f"[FTP Sensor] engine stopped: {exc}")
