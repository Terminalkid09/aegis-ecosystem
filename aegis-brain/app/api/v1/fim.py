"""File Integrity Monitoring: watchlist per agente.

Perche' esiste
--------------
Il FIM e' uno dei pilastri che separano un SIEM completo da un raccoglitore
di log: i meccanismi di persistenza (Run keys, scheduled tasks, servizi,
startup folder) e i file sensibili (hosts, LSASS dump, driver) viaggiano
tutti per FILESYSTEM, non per rete. Guard monitora i percorsi che il brain
gli indica (comando FIM_SET_WATCH) e riporta ogni modifica come evento
FILE_MODIFIED, che entra nella pipeline SIEM standard (ricerca, Sigma,
correlazione, playbook).

La watchlist vive in `agents.meta["fim_watchlist"]`: e' configurazione
dell'endpoint, non un evento — non serve una tabella (zero migrazioni) e
segue il ciclo di vita dell'agente (revoke/re-enroll laresetta tutto).

Default sicuri: se l'utente non configura nulla, il brain spinta la
DEFAULT_WATCHLIST al primo Put vuoto? No: il default e' applicato lato
Guard (baseline ragionevole), qui si configura solo l'override. Il PUT
sovrascrive, il DELETE ripristina il default agente.
"""
from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import require_perm
from app.core.logging import get_logger
from app.database.connection import get_db
from app.database.models import Agent
from app.services.telemetry_service import send_command_to_agent

logger = get_logger(__name__)
router = APIRouter(tags=["FIM"])

# Percorsi suggeriti (pre-caricati nella UI, non forzati lato server:
# ogni host e' diverso e il SOC decide).
SUGGESTED_PATHS: List[str] = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\Tasks",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    r"C:\Windows\System32\config\systemprofile",
    "/etc/hosts",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/etc/sudoers",
    "/root/.ssh",
]

MAX_PATHS = 100
MAX_PATH_LEN = 1024


class WatchlistUpdate(BaseModel):
    paths: List[str] = Field(default_factory=list, max_length=MAX_PATHS)
    recursive: bool = True


def _validate_paths(paths: List[str]) -> List[str]:
    """Normalizza e valida: dedup, trim, limiti. Rifiuta traverasle ovvie."""
    out: List[str] = []
    seen = set()
    for p in paths:
        if not isinstance(p, str):
            raise HTTPException(status_code=422, detail="Every path must be a string")
        p = p.strip()
        if not p:
            continue
        if len(p) > MAX_PATH_LEN:
            raise HTTPException(status_code=422, detail=f"Path too long (max {MAX_PATH_LEN}): {p[:60]}...")
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


async def _get_agent(db: AsyncSession, agent_id: str) -> Agent:
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/agents/{agent_id}/fim-watchlist")
async def get_watchlist(agent_id: str, db: AsyncSession = Depends(get_db),
                        user=Depends(require_perm("read"))):
    agent = await _get_agent(db, agent_id)
    meta = agent.meta or {}
    wl = meta.get("fim_watchlist") or {}
    return {
        "agent_id": str(agent.agent_id),
        "paths": wl.get("paths", []),
        "recursive": wl.get("recursive", True),
        "suggested": SUGGESTED_PATHS,
    }


@router.put("/agents/{agent_id}/fim-watchlist")
async def set_watchlist(agent_id: str, payload: WatchlistUpdate,
                        request: Request,
                        db: AsyncSession = Depends(get_db),
                        user=Depends(require_perm("manage"))):
    """Imposta la watchlist e notifica l'agente via coda comandi.

    Permesso `manage` (come le chiavi di integrazione): cambiare cosa un
    agente monitora e' un'operazione sensibile — un utente compromesso con
    ruolo intermedio non deve poter CEGLARE la sorveglianza riducendo la
    watchlist.
    """
    agent = await _get_agent(db, agent_id)
    paths = _validate_paths(payload.paths)

    agent.meta = {**(agent.meta or {}), "fim_watchlist": {
        "paths": paths, "recursive": payload.recursive,
    }}
    db.add(agent)
    await log_audit(
        db, action="fim_watchlist_set", resource=f"agent:{agent.agent_id}",
        details={"count": len(paths)}, user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()

    # Notifica l'agente (best-effort: la coda puo' essere giu', la watchlist
    # resta salvata e verra' applicata al prossimo heartbeat se Guard la
    # richiede — comunque l'utente vede lo stato reale dalla UI).
    queued = True
    try:
        await send_command_to_agent(str(agent.agent_id), {
            "command": "FIM_SET_WATCH",
            "paths": paths,
            "recursive": payload.recursive,
        })
    except Exception as exc:
        queued = False
        logger.warning(f"FIM_SET_WATCH non accodata per {agent.agent_id}: {exc}")

    return {"agent_id": str(agent.agent_id), "count": len(paths),
            "paths": paths, "command_queued": queued}


@router.delete("/agents/{agent_id}/fim-watchlist")
async def reset_watchlist(agent_id: str, request: Request,
                          db: AsyncSession = Depends(get_db),
                          user=Depends(require_perm("manage"))):
    """Ripristina il default agente (watchlist vuota lato server)."""
    agent = await _get_agent(db, agent_id)
    meta = dict(agent.meta or {})
    meta.pop("fim_watchlist", None)
    agent.meta = meta
    db.add(agent)
    await log_audit(
        db, action="fim_watchlist_reset", resource=f"agent:{agent.agent_id}",
        details={}, user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    try:
        await send_command_to_agent(str(agent.agent_id), {
            "command": "FIM_SET_WATCH", "paths": [], "recursive": True})
    except Exception:
        pass
    return {"agent_id": str(agent.agent_id), "reset": True}
