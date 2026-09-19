"""Impostazioni notifiche Telegram (Platform Settings -> Telegram).

Le impostazioni non segrete vivono in app_settings (chat_id, enable,
severita' minima, heartbeat); il bot token e' un segreto e sta in
integration_settings (cifrato col KEK). Scrittura riservata a `manage`
come le altre scelte di postura: decide se il contenuto degli alert esce
dalla rete.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user, has_perm
from app.core.rate_limit import limiter
from app.database.connection import get_db
from app.database.models import User
from app.services import app_settings, integration_settings, telegram_notifier

router = APIRouter(tags=["Telegram"])


def _payload(db_state: dict) -> dict:
    return {
        "enabled": db_state.get("telegram.enabled", "false").lower() == "true",
        "chat_id": db_state.get("telegram.chat_id", ""),
        "min_severity": (db_state.get("telegram.min_severity") or "HIGH").upper(),
        "heartbeat_minutes": int(db_state.get("telegram.heartbeat_minutes") or 60),
        "bot_token_configured": None,  # riempito dal chiamante
    }


@router.get("/settings")
@limiter.limit("30/minute")
async def get_telegram_settings(
        request: Request,
        db: AsyncSession = Depends(get_db),
        user: User = Depends(get_current_user),
):
    """Stato corrente: valori, origine e se il bot token e' configurato."""
    keys = ["telegram.enabled", "telegram.chat_id", "telegram.min_severity",
            "telegram.heartbeat_minutes"]
    state = {}
    origins = {}
    for k in keys:
        val, origin = await app_settings.get_value_with_origin(db, k, "")
        state[k] = val
        origins[k] = origin
    token, _tok_origin = await integration_settings.get_key_with_origin(db, "telegram_bot_token")
    out = _payload(state)
    out["bot_token_configured"] = bool(token)
    out["origins"] = origins
    return out


@router.put("/settings")
@limiter.limit("10/minute")
async def set_telegram_settings(
        request: Request,
        payload: dict,
        db: AsyncSession = Depends(get_db),
        user: User = Depends(get_current_user),
):
    """Scrive enable/chat_id/min_severity/heartbeat e invalida la cache."""
    if not has_perm(user.role, "manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient permissions")

    changed = {}
    if "enabled" in payload:
        val = "true" if payload["enabled"] in (True, "true", "True", 1) else "false"
        await app_settings.set_value(db, "telegram.enabled", val, user.id)
        changed["enabled"] = val == "true"

    if "chat_id" in payload:
        chat_id = str(payload["chat_id"]).strip().lstrip("@")
        # chat_id valido: numerico (anche negativo per gruppi) o @nomepubblico
        if chat_id and not (chat_id.lstrip("-").isdigit() or
                            (chat_id.startswith("@") and 5 <= len(chat_id) <= 64)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="chat_id must be numeric (or negative for groups) or @publicname")
        await app_settings.set_value(db, "telegram.chat_id", chat_id, user.id)
        changed["chat_id"] = chat_id or None

    if "min_severity" in payload:
        sev = str(payload["min_severity"]).strip().upper()
        if sev not in ("HIGH", "CRITICAL"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="min_severity must be HIGH or CRITICAL")
        await app_settings.set_value(db, "telegram.min_severity", sev, user.id)
        changed["min_severity"] = sev

    if "heartbeat_minutes" in payload:
        try:
            minutes = int(payload["heartbeat_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="heartbeat_minutes must be an integer")
        if not 15 <= minutes <= 1440:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="heartbeat_minutes must be between 15 and 1440")
        await app_settings.set_value(db, "telegram.heartbeat_minutes", str(minutes), user.id)
        changed["heartbeat_minutes"] = minutes

    await db.commit()
    telegram_notifier.invalidate_cache()
    return {"status": "updated", "changed": changed}


@router.post("/test")
@limiter.limit("5/minute")
async def send_test(
        request: Request,
        db: AsyncSession = Depends(get_db),
        user: User = Depends(get_current_user),
):
    """Invia un messaggio di prova: verifica token+chat senza aspettare un alert."""
    if not has_perm(user.role, "manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient permissions")
    result = await telegram_notifier.send_test_message(db)
    if not result.get("ok"):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=result.get("error", "test failed"))
    return {"status": "sent", "detail": "Check your Telegram chat."}
