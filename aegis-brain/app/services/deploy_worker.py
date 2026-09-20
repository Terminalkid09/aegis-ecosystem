"""Deploy worker boundary.

Password-based remote execution is deliberately disabled until an ephemeral
credential broker and host-key pinning are available. Jobs created through the
API therefore use signed, manual one-line enrollment and are not reported as
running when no executor exists.

Worker loop (to run as sidecar or lifespan task):
  poll deploy_jobs WHERE status=queued -> mark running ->
  for each target: attempt transport -> PUT results via update_job_status logic
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

# Transports are optional deps — worker degrades to queued+instructions
# if asyncssh/pywinrm are not installed.
try:  # pragma: no cover
    import asyncssh  # type: ignore  # noqa: F401 — capability probe only
    HAS_SSH = True
except Exception:
    HAS_SSH = False


async def execute_job(job_id: int) -> dict:
    """Return an honest capability result without pretending to deploy."""
    return {
        "job_id": job_id,
        "status": "manual_required",
        "transports": {"ssh": HAS_SSH, "winrm": False},
        "note": "Use signed one-line enrollment; password-based execution is disabled.",
        "at": datetime.now(timezone.utc).isoformat(),
    }


async def poll_once() -> int:
    await asyncio.sleep(0)
    return 0
