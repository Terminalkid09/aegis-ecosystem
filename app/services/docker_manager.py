import asyncio
from typing import Dict, List, Optional, Tuple

import httpx
from loguru import logger

from app.core.config import settings
from app.services.sample_archive import safe_extract as _safe_extract


class DockerManager:
    """Talk to the sandbox broker; this process never receives the Docker socket."""

    def __init__(self):
        self._active: Dict[str, Tuple[str, asyncio.Task]] = {}
        self._lock = asyncio.Lock()

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        if not settings.SANDBOX_BROKER_URL:
            raise RuntimeError("SANDBOX_BROKER_URL is not configured")
        headers = {"Authorization": f"Bearer {settings.SANDBOX_BROKER_TOKEN}"}
        async with httpx.AsyncClient(
            base_url=settings.SANDBOX_BROKER_URL.rstrip("/"),
            headers=headers,
            timeout=30.0,
        ) as client:
            response = await client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()

    async def create_sandbox(self, session_id: str) -> Optional[Dict]:
        # The capacity check and registration must be atomic.
        async with self._lock:
            if len(self._active) >= settings.SANDBOX_MAX_CONCURRENT:
                logger.warning("Max concurrent sandboxes reached — rejecting.")
                return None
            try:
                result = await asyncio.wait_for(self._create(session_id), timeout=10.0)
                if result:
                    watchdog_task = asyncio.create_task(self._watchdog(session_id))
                    self._active[session_id] = (result["container_id"], watchdog_task)
                return result
            except asyncio.TimeoutError:
                logger.error(f"Sandbox creation timed out for session {session_id}")
                return None
            except Exception as e:
                logger.error(f"create_sandbox error: {e}")
                return None

    async def _create(self, session_id: str) -> Optional[Dict]:
        return await self._request("POST", "/v1/sandboxes", json={"session_id": session_id})

    async def destroy_sandbox(self, session_id: str):
        async with self._lock:
            entry = self._active.pop(session_id, None)
            if entry is None:
                return
            container_id, watchdog_task = entry
            watchdog_task.cancel()
        await self._destroy(container_id, session_id)

    async def _destroy(self, container_id: str, session_id: str):
        try:
            result = await self._request("DELETE", f"/v1/sandboxes/{container_id}")
            for sample in result.get("samples", []):
                logger.info(
                    f"Malware captured: {sample['filename']} ({sample['sha256']})"
                )
                from app.core.metrics import record_malware_captured
                record_malware_captured(sample["sha256"])
                from app.services.siem import siem_logger
                siem_logger.log_malware({
                    "session_id": session_id,
                    "filename": sample["filename"],
                    "sha256": sample["sha256"],
                    "size": sample["size"],
                    "path": sample["path"],
                })
        except Exception as e:
            logger.error(f"Broker could not destroy {container_id[:12]}: {e}")

    async def exec_command(self, session_id: str, cmd: str) -> str:
        async with self._lock:
            entry = self._active.get(session_id)
            if entry is None:
                return ""
            container_id = entry[0]
        try:
            result = await self._request(
                "POST",
                f"/v1/sandboxes/{container_id}/exec",
                json={"cmd": cmd},
            )
            return result.get("output", "")
        except Exception as e:
            logger.error(f"Sandbox exec failed: {e}")
            return ""

    async def _watchdog(self, session_id: str):
        try:
            await asyncio.sleep(settings.SANDBOX_MAX_LIFETIME)
            await self.destroy_sandbox(session_id)
        except asyncio.CancelledError:
            pass

    async def list_active(self) -> List[Dict]:
        try:
            result = await self._request("GET", "/v1/sandboxes")
            return result if isinstance(result, list) else result.get("sandboxes", [])
        except Exception as e:
            logger.error(f"Error listing sandboxes: {e}")
            return []


docker_manager = DockerManager()
