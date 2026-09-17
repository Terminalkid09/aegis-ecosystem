from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database.connection import get_db
from app.core.deps import get_current_user, has_perm
from app.core.audit import log_audit
from app.services import integration_settings as isvc

router = APIRouter(tags=["Integrations"])


class SetKeyRequest(BaseModel):
    provider: str = Field(..., min_length=1, max_length=64)
    value: str = Field("", max_length=512)  # "" = cancella l'override


@router.get("/settings")
async def get_integration_settings(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Stato dei provider con chiavi mascherate: la UI genera i campi da qui.

    Lettura consentita a qualunque utente autenticato (non espone chiavi,
    solo mascheramento e origine): la scrittura è riservata a `manage`.
    """
    return {"providers": await isvc.get_provider_status(db)}


@router.put("/settings")
async def set_integration_key(
    payload: SetKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    if not has_perm(user.role, "manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient permissions")
    spec = isvc.PROVIDERS.get(payload.provider)
    if spec is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Unknown provider: {payload.provider}")
    await isvc.set_key(db, payload.provider, payload.value, updated_by=user.id)
    await log_audit(
        db, action="integration_key_set", resource="integration",
        resource_id=payload.provider,
        details={"provider": payload.provider, "cleared": not payload.value},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    return {"status": "ok", "provider": payload.provider,
            "cleared": not payload.value}
