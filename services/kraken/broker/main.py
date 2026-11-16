import hmac
import io
import os
import re
import tarfile

import docker
import docker.errors
from fastapi import Depends, FastAPI, Header, HTTPException
from loguru import logger
from pydantic import BaseModel, Field

from app.services.retention import prune_malware
from app.services.sample_archive import safe_extract
from app.services.sandbox_policy import SANDBOX_RUN_KWARGS

BROKER_TOKEN = os.getenv("SANDBOX_BROKER_TOKEN", "")
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "kraken_sandbox")
MALWARE_DIR = os.getenv("MALWARE_DIR", "/app/data/malware")
MAX_FILE_BYTES = int(os.getenv("MALWARE_MAX_FILE_BYTES", str(64 * 1024 * 1024)))
MAX_SESSION_BYTES = int(os.getenv("MALWARE_MAX_SESSION_BYTES", str(256 * 1024 * 1024)))
RETENTION_DAYS = int(os.getenv("MALWARE_RETENTION_DAYS", "30"))
MAX_TOTAL_BYTES = int(os.getenv("MALWARE_MAX_TOTAL_BYTES", str(5 * 1024 * 1024 * 1024)))
MAX_EXEC_OUTPUT = 1 * 1024 * 1024
SESSION_RE = re.compile(r"^[\w\-]{8,64}$")

_client = None


def get_client():
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


app = FastAPI(title="Kraken Sandbox Broker", docs_url=None, redoc_url=None)


def authorize(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {BROKER_TOKEN}"
    if not BROKER_TOKEN or not hmac.compare_digest(
        authorization.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Invalid broker token.")


class SandboxRequest(BaseModel):
    session_id: str = Field(..., min_length=8, max_length=64)


class ExecRequest(BaseModel):
    cmd: str = Field(..., min_length=1, max_length=512)


def _managed_container(container_id: str):
    try:
        container = get_client().containers.get(container_id)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Sandbox not found.")
    if container.labels.get("kraken.managed") != "true":
        raise HTTPException(status_code=404, detail="Sandbox not found.")
    return container


def _capture(container) -> list[dict]:
    os.makedirs(MALWARE_DIR, exist_ok=True)
    samples: list[dict] = []
    try:
        diff = container.diff() or []
    except Exception as e:
        logger.error(f"diff failed: {e}")
        return samples
    allowed_prefixes = ("/tmp/", "/var/tmp/", "/root/", "/home/sandbox/")
    for item in diff:
        if item.get("Kind") not in (0, 1):
            continue
        path = item.get("Path")
        if not path or not any(path.startswith(prefix) for prefix in allowed_prefixes):
            continue
        try:
            bits, stat = container.get_archive(path)
            archive_size = (stat or {}).get("size", 0)
            if archive_size > MAX_SESSION_BYTES:
                logger.warning(f"Skipping oversized archive {path} ({archive_size} bytes)")
                continue
            buffer = bytearray()
            for chunk in bits:
                if len(buffer) + len(chunk) > MAX_SESSION_BYTES:
                    logger.warning(f"Skipping oversized archive stream {path}")
                    buffer.clear()
                    break
                buffer.extend(chunk)
            if not buffer:
                continue
            with tarfile.open(fileobj=io.BytesIO(buffer)) as tar:
                samples.extend(
                    safe_extract(
                        tar,
                        MALWARE_DIR,
                        max_file_bytes=MAX_FILE_BYTES,
                        max_total_bytes=MAX_SESSION_BYTES,
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to extract {path}: {e}")
    prune_malware(MALWARE_DIR, RETENTION_DAYS, MAX_TOTAL_BYTES)
    return samples


@app.get("/health")
def health():
    try:
        get_client().ping()
    except Exception as e:
        logger.error(f"Docker daemon unreachable: {e}")
        raise HTTPException(status_code=503, detail="Docker daemon unreachable.")
    return {"status": "ok"}


@app.get("/v1/sandboxes", dependencies=[Depends(authorize)])
def list_sandboxes():
    containers = get_client().containers.list(filters={"label": "kraken.managed=true"})
    return [
        {
            "id": c.id[:12],
            "container_id": c.id,
            "name": c.name,
            "status": c.status,
            "session_id": c.labels.get("kraken.session", "?"),
        }
        for c in containers
    ]


@app.post("/v1/sandboxes", dependencies=[Depends(authorize)])
def create_sandbox(payload: SandboxRequest):
    if not SESSION_RE.match(payload.session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format.")
    existing = get_client().containers.list(
        filters={"label": f"kraken.session={payload.session_id}"}, all=True
    )
    if existing:
        container = existing[0]
        return {
            "container_id": container.id,
            "name": container.name,
            "ip": None,
        }
    name = f"kraken_sb_{payload.session_id[:12]}"
    try:
        container = get_client().containers.run(
            image=SANDBOX_IMAGE,
            name=name,
            detach=True,
            labels={
                "kraken.managed": "true",
                "kraken.session": payload.session_id,
            },
            **SANDBOX_RUN_KWARGS,
        )
    except docker.errors.ImageNotFound:
        raise HTTPException(status_code=503, detail="Sandbox image not found.")
    except docker.errors.APIError as e:
        logger.error(f"Docker APIError: {e}")
        raise HTTPException(status_code=503, detail="Could not create sandbox.")
    logger.info(f"Sandbox {name} created (network=none, read-only)")
    return {"container_id": container.id, "name": name, "ip": None}


@app.post("/v1/sandboxes/{container_id}/exec", dependencies=[Depends(authorize)])
def exec_command(container_id: str, payload: ExecRequest):
    container = _managed_container(container_id)
    try:
        result = container.exec_run(["sh", "-c", payload.cmd])
        output = result.output or b""
        if isinstance(output, bytes):
            output = output.decode(errors="ignore")
        return {"output": output[:MAX_EXEC_OUTPUT]}
    except Exception as e:
        logger.error(f"exec failed: {e}")
        raise HTTPException(status_code=503, detail="Sandbox exec failed.")


@app.delete("/v1/sandboxes/{container_id}", dependencies=[Depends(authorize)])
def destroy_sandbox(container_id: str):
    container = _managed_container(container_id)
    samples = _capture(container)
    try:
        container.stop(timeout=5)
        container.remove(force=True)
    except docker.errors.NotFound:
        pass
    logger.info(f"Sandbox {container_id[:12]} removed.")
    return {"samples": samples}
