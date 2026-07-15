import asyncio
import os
import hashlib
import tarfile
import io
from typing import Optional, Dict, List, Tuple
from loguru import logger
import docker
import docker.errors
from app.core.config import settings


def _safe_extract(tar: tarfile.TarFile, dest: str) -> list[dict]:
    """Safely extract tar members, preventing path traversal."""
    results = []
    for member in tar.getmembers():
        name = os.path.normpath(member.name)
        if name.startswith("/") or ".." in name.split(os.sep):
            continue
        f = tar.extractfile(member)
        if f is None:
            continue
        content = f.read()
        f.close()
        sha256_hash = hashlib.sha256(content).hexdigest()
        safe_path = os.path.join(dest, sha256_hash)
        with open(safe_path, "wb") as out:
            out.write(content)
        results.append({
            "sha256": sha256_hash,
            "size": len(content),
            "path": safe_path,
            "filename": os.path.basename(member.name)
        })
    return results


# ── Shared synchronous Docker client (reused, not created per call) ───────────

_sync_client: Optional[docker.DockerClient] = None


def _get_sync_client() -> Optional[docker.DockerClient]:
    global _sync_client
    if _sync_client is None:
        try:
            _sync_client = docker.from_env()
        except Exception as e:
            logger.error(f"Docker daemon not reachable: {e}")
    return _sync_client


class DockerManager:
    def __init__(self):
        self._active: Dict[str, Tuple[str, asyncio.Task]] = {}
        self._lock = asyncio.Lock()

    async def create_sandbox(self, session_id: str) -> Optional[Dict]:
        if len(self._active) >= settings.SANDBOX_MAX_CONCURRENT:
            logger.warning("Max concurrent sandboxes reached — rejecting.")
            return None
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._create, session_id),
                timeout=10.0,
            )
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

    async def destroy_sandbox(self, session_id: str):
        async with self._lock:
            entry = self._active.pop(session_id, None)
            if entry is None:
                return
            container_id, watchdog_task = entry
            watchdog_task.cancel()
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._destroy, container_id, session_id)

    async def exec_command(self, session_id: str, cmd: str) -> str:
        async with self._lock:
            entry = self._active.get(session_id)
            if entry is None:
                return ""
            container_id = entry[0]
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._exec, container_id, cmd)

    async def _watchdog(self, session_id: str):
        try:
            await asyncio.sleep(settings.SANDBOX_MAX_LIFETIME)
            await self.destroy_sandbox(session_id)
        except asyncio.CancelledError:
            pass

    async def list_active(self) -> List[Dict]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list)

    # ── Sync internals (run in executor) ──────────────────────────────────────

    def _create(self, session_id: str) -> Optional[Dict]:
        client = _get_sync_client()
        if not client:
            return None
        name = f"kraken_sb_{session_id[:12]}"
        try:
            container = client.containers.run(
                image=settings.SANDBOX_IMAGE,
                name=name,
                detach=True,
                network=settings.SANDBOX_NETWORK,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                mem_limit="128m",
                pids_limit=64,
                cpu_period=100000,
                cpu_quota=25000,
                read_only=False,
                labels={"kraken.managed": "true", "kraken.session": session_id},
            )
            container.reload()
            nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            ip = next((n.get("IPAddress") for n in nets.values() if n.get("IPAddress")), None)
            logger.info(f"Sandbox {name} created (ip={ip})")
            return {"container_id": container.id, "name": name, "ip": ip}
        except docker.errors.ImageNotFound:
            logger.error(f"Image '{settings.SANDBOX_IMAGE}' not found — build it first.")
        except docker.errors.APIError as e:
            logger.error(f"Docker APIError: {e}")
        return None

    def _exec(self, container_id: str, cmd: str) -> str:
        client = _get_sync_client()
        if not client:
            return ""
        try:
            c = client.containers.get(container_id)
            res = c.exec_run(["sh", "-c", cmd])
            output = res.output
            if isinstance(output, bytes):
                output = output.decode(errors="ignore")
            return output
        except Exception:
            return ""

    def _destroy(self, container_id: str, session_id: str):
        client = _get_sync_client()
        if not client:
            return
        try:
            c = client.containers.get(container_id)

            # --- Malware Capture ---
            try:
                diff = c.diff()
                if diff:
                    malware_dir = settings.MALWARE_DIR
                    os.makedirs(malware_dir, exist_ok=True)
                    for item in diff:
                        if item.get("Kind") in (0, 1):
                            path = item.get("Path")
                            allowed_prefixes = ("/tmp/", "/var/tmp/", "/root/", "/home/sandbox/")
                            if path and any(path.startswith(p) for p in allowed_prefixes):
                                try:
                                    bits, stat = c.get_archive(path)
                                    file_data = b"".join(bits)
                                    with tarfile.open(fileobj=io.BytesIO(file_data)) as tar:
                                        results = _safe_extract(tar, malware_dir)
                                        for r in results:
                                            logger.info(f"Malware captured: {r['filename']} ({r['sha256']})")
                                            from app.services.siem import siem_logger
                                            siem_logger.log_malware({
                                                "session_id": session_id,
                                                "filename": r["filename"],
                                                "sha256": r["sha256"],
                                                "size": r["size"],
                                                "path": r["path"]
                                            })
                                except Exception as e:
                                    logger.warning(f"Failed to extract {path}: {e}")
            except Exception as e:
                logger.error(f"Malware capture error: {e}")
            # -------------------------

            c.stop(timeout=5)
            c.remove(force=True)
            logger.info(f"Sandbox {container_id[:12]} removed.")
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logger.error(f"Error removing container {container_id[:12]}: {e}")

    def _list(self) -> List[Dict]:
        client = _get_sync_client()
        if not client:
            return []
        try:
            containers = client.containers.list(filters={"label": "kraken.managed=true"})
            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                    "session_id": c.labels.get("kraken.session", "?"),
                }
                for c in containers
            ]
        except Exception as e:
            logger.error(f"Error listing containers: {e}")
            return []


docker_manager = DockerManager()
