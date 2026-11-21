import asyncio
import asyncssh
import uuid
import httpx
import os
from pathlib import Path
from loguru import logger
from app.core.config import settings

_http_client: httpx.AsyncClient = None
_API_BASE = settings.SANDBOX_API_URL.rsplit("/containers", 1)[0]


async def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0))
    return _http_client


def _api_headers() -> dict:
    return {"X-Internal-API-Key": settings.INTERNAL_API_KEY}


async def _post_ingest(payload: dict):
    try:
        client = await _get_http_client()
        await client.post(
            f"{_API_BASE}/events/ingest",
            json=payload,
            headers=_api_headers(),
        )
    except Exception as e:
        logger.error(f"Ingest report failed: {e}")


async def _sandbox_create(session_id: str) -> dict:
    try:
        client = await _get_http_client()
        resp = await client.post(
            f"{_API_BASE}/containers/create",
            params={"session_id": session_id},
            headers=_api_headers(),
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.error(f"Sandbox create failed: {e}")
    return None


async def _sandbox_exec(session_id: str, cmd: str) -> str:
    try:
        client = await _get_http_client()
        resp = await client.post(
            f"{_API_BASE}/containers/exec",
            params={"session_id": session_id, "cmd": cmd},
            headers=_api_headers(),
        )
        if resp.status_code == 200:
            return resp.json().get("output", "")
    except Exception as e:
        logger.error(f"Sandbox exec failed: {e}")
    return ""


async def _sandbox_destroy(session_id: str):
    try:
        client = await _get_http_client()
        await client.delete(
            f"{_API_BASE}/containers/{session_id}",
            headers=_api_headers(),
        )
    except Exception as e:
        logger.error(f"Sandbox destroy failed: {e}")


class KrakenSSHServer(asyncssh.SSHServer):
    def __init__(self, session_id, ip, port):
        self.session_id = session_id
        self.ip = ip
        self.port = port
        self.username = None
        self.password = None
        self.commands = []

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        self.ip, self.port = peer[0], peer[1]
        conn._kraken_server = self
        logger.info(f"[SSH] Connection from {self.ip}:{self.port} - session {self.session_id}")

    def connection_lost(self, exc):
        asyncio.create_task(_post_ingest({
            "sensor_type": "ssh",
            "attacker_ip": self.ip,
            "attacker_port": self.port,
            "sensor_port": settings.SSH_SENSOR_PORT,
            "session_id": self.session_id,
            "username": self.username,
            "password": self.password,
            "commands": self.commands,
        }))

    def begin_auth(self, username):
        self.username = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.username = username
        self.password = password
        return True


def server_factory():
    # asyncssh calls the factory without arguments for every new connection;
    # peer details are available in SSHServer.connection_made(conn).
    return KrakenSSHServer(str(uuid.uuid4()), "unknown", 0)


async def handle_client(process):
    server = getattr(process.channel.get_connection(), "_kraken_server", None)
    if server is None:
        logger.error("[SSH] Process started without server context")
        process.exit(1)
        return
    session_id = server.session_id

    process.stdout.write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)\n\n")

    sandbox = await _sandbox_create(session_id)

    while True:
        try:
            process.stdout.write("root@ubuntu:~# ")
            line = await process.stdin.readline()
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                continue

            if len(server.commands) < 200:
                server.commands.append(cmd)

            if cmd in ("exit", "logout", "quit"):
                break

            if sandbox:
                output = await _sandbox_exec(session_id, cmd)
                if output:
                    process.stdout.write(output)
                    if not output.endswith('\n'):
                        process.stdout.write("\n")
                else:
                    process.stdout.write(f"bash: {cmd}: command not found\n")
            else:
                process.stdout.write(f"bash: {cmd}: command not found\n")

        except asyncssh.BreakReceived:
            break
        except Exception as e:
            logger.error(f"SSH process error: {e}")
            break

    process.exit(0)
    if sandbox:
        await _sandbox_destroy(session_id)


class SSHSensor:
    def __init__(self, host: str = "0.0.0.0", port: int = None):
        self.host = host
        self.port = port or settings.SSH_SENSOR_PORT

    async def start(self):
        Path(settings.DATA_DIR).mkdir(parents=True, exist_ok=True)
        key_path = str(Path(settings.DATA_DIR) / "ssh_host_ed25519_key")
        if not os.path.exists(key_path):
            key = asyncssh.generate_private_key("ssh-ed25519")
            key.write_private_key(key_path)

        await asyncssh.create_server(
            server_factory,
            self.host,
            self.port,
            server_host_keys=[key_path],
            server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            process_factory=handle_client,
        )
        logger.info(f"[SSH Sensor] Listening on {self.host}:{self.port}")
        await asyncio.Event().wait()
