import hmac
import re
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.docker_manager import docker_manager
from app.api.v1.endpoints.deps import get_current_user
from app.core.security import decode_access_payload
from app.core.config import settings
from app.db.redis import is_token_blacklisted
from app.db.session import get_db
from app.models.models import User

_VALID_SESSION_ID = re.compile(r"^[\w\-]{8,64}$")

router = APIRouter(prefix="/containers", tags=["containers"])


async def _get_admin_or_internal(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> str:
    """Allow either valid admin JWT (cookie/Bearer) OR valid internal API key."""
    api_key = request.headers.get("X-Internal-API-Key", "")
    if api_key and settings.INTERNAL_API_KEY:
        if hmac.compare_digest(
            api_key.encode("utf-8"), settings.INTERNAL_API_KEY.encode("utf-8")
        ):
            return api_key

    token = request.cookies.get("kraken_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if token:
        payload = decode_access_payload(token)
        if payload:
            jti = payload.get("jti")
            if not jti:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
            if await is_token_blacklisted(jti):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked.")
            username = payload.get("sub")
            if username:
                result = await db.execute(select(User).where(User.username == username))
                user = result.scalar_one_or_none()
                if user and user.is_active and user.is_admin:
                    return username

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin JWT or valid internal API key required.",
    )


@router.get("/active")
async def list_active(_=Depends(get_current_user)):
    """List all currently active sandbox containers."""
    return await docker_manager.list_active()


@router.post("/create")
async def create(
    session_id: str = Query(..., min_length=8, max_length=64),
    _auth=Depends(_get_admin_or_internal),
):
    """Create a sandbox (admin or internal API key)."""
    if not _VALID_SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")
    result = await docker_manager.create_sandbox(session_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Could not create sandbox.")
    return result


@router.post("/exec")
async def exec_command(
    session_id: str = Query(..., min_length=8, max_length=64),
    cmd: str = Query(..., max_length=512),
    _auth=Depends(_get_admin_or_internal),
):
    """Execute a command in a running sandbox."""
    if not _VALID_SESSION_ID.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format")
    output = await docker_manager.exec_command(session_id, cmd)
    return {"output": output}


@router.delete("/{session_id}")
async def destroy(
    session_id: str,
    _auth=Depends(_get_admin_or_internal),
):
    """Destroy a sandbox (admin or internal API key)."""
    await docker_manager.destroy_sandbox(session_id)
    return {"status": "destroyed", "session_id": session_id}
