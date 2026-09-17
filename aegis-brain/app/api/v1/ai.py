from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import get_current_user, has_perm
from app.core.audit import log_audit
from app.services import ai_service, app_settings
from app.database.connection import get_db
from app.database.models import AIMessage, AIThread, User
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter(tags=["AI-Suite"])



class ChatRequest(BaseModel):
    prompt: str = Field(..., max_length=8000)
    model: Optional[str] = Field(None, max_length=100)
    thread_id: Optional[int] = None
    title: Optional[str] = Field(None, max_length=255)

async def get_or_create_thread(db: AsyncSession, user: User, thread_id: Optional[int], prompt: str, title: Optional[str] = None) -> AIThread:
    if thread_id is not None:
        try:
            thread_id_int = int(thread_id)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid thread_id")
        result = await db.execute(select(AIThread).where(AIThread.id == thread_id_int, AIThread.user_id == user.id))
        thread = result.scalars().first()
        if not thread:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI thread not found")
        return thread

    thread_title = title or prompt.strip().splitlines()[0][:80] or "Security Investigation"
    thread = AIThread(user_id=user.id, title=thread_title)
    db.add(thread)
    await db.commit()
    await db.refresh(thread)
    return thread

@router.get("/status")
async def ai_status(user: User = Depends(get_current_user)):
    """Provider AI effettivo, modello e se i dati escono dalla rete.

    La UI lo mostra in Settings: con AI disattivata non si vedono errori a
    raffica, si vede lo stato con il motivo (e come attivarla).
    """
    return await ai_service.provider_summary()


class AISettingsRequest(BaseModel):
    """Campi opzionali: `None` = non toccare, `""` = torna al default/env."""
    provider: Optional[str] = Field(None, max_length=32)
    model: Optional[str] = Field(None, max_length=200)
    automatic_enrich: Optional[bool] = None


@router.get("/settings")
async def get_ai_settings(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Impostazioni AI per la UI: valori correnti, origine e opzioni.

    Include lo stato live (`status`) cosi' la dashboard mostra in un colpo
    solo cosa e' configurato e cosa sta rispondendo davvero.
    """
    payload = await app_settings.settings_payload(db)
    payload["status"] = await ai_service.provider_summary()
    return payload


@router.put("/settings")
async def set_ai_settings(
    payload: AISettingsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Scrive le impostazioni AI (provider, modello, arricchimento automatico).

    Scrittura riservata a `manage`: e' una scelta di postura (decide se il
    contenuto degli alert puo' uscire dalla rete), non una preferenza utente.
    La chiave API resta in `integration_settings`.
    """
    if not has_perm(user.role, "manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient permissions")

    changed = {}
    if payload.provider is not None:
        value = payload.provider.strip().lower()
        if value and not app_settings.validate_provider(value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown provider: {value}. "
                       f"Allowed: {', '.join(app_settings.AI_PROVIDERS)}",
            )
        # `auto` E' il default: salvarlo come riga non aggiunge nulla e farebbe
        # dire alla UI "origine: dashboard" su un valore che e' il default della
        # piattaforma. Sceglierlo pulisce l'override e basta.
        stored = "" if value in ("", "auto") else value
        await app_settings.set_value(db, app_settings.KEY_PROVIDER, stored, user.id)
        changed["provider"] = value or "default"

    if payload.model is not None:
        await app_settings.set_value(db, app_settings.KEY_MODEL,
                                     payload.model.strip(), user.id)
        changed["model"] = payload.model.strip() or "default"

    if payload.automatic_enrich is not None:
        await app_settings.set_value(db, app_settings.KEY_AUTOMATIC,
                                     "true" if payload.automatic_enrich else "false",
                                     user.id)
        changed["automatic_enrich"] = payload.automatic_enrich

    if changed:
        await log_audit(
            db, action="ai_settings_set", resource="ai", resource_id="settings",
            details=changed, user_id=user.id, username=user.username,
            ip_address=request.client.host if request else None,
        )
    await db.commit()

    result = await app_settings.settings_payload(db)
    result["status"] = await ai_service.provider_summary()
    result["changed"] = changed
    return result


@router.get("/threads")
async def list_threads(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100)
):
    result = await db.execute(
        select(AIThread)
        .where(AIThread.user_id == user.id)
        .order_by(AIThread.updated_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": thread.id,
            "title": thread.title,
            "created_at": thread.created_at,
            "updated_at": thread.updated_at,
        }
        for thread in result.scalars().all()
    ]

@router.get("/threads/{thread_id}/messages")
async def list_thread_messages(
    thread_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    result = await db.execute(select(AIThread).where(AIThread.id == thread_id, AIThread.user_id == user.id))
    if not result.scalars().first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI thread not found")

    messages = await db.execute(
        select(AIMessage)
        .where(AIMessage.thread_id == thread_id)
        .order_by(AIMessage.created_at.asc())
    )
    return [
        {
            "id": message.id,
            "role": message.role,
            "content": message.content,
            "model": message.model,
            "created_at": message.created_at,
        }
        for message in messages.scalars().all()
    ]

@router.post("/chat")
async def ai_chat(payload: ChatRequest, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    if not await ai_service.check_rate_limit(user.id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    try:
        # Audit: si persiste SOLO il prompt anonimizzato (mai PII raw in DB).
        safe_prompt = ai_service.anonymize_prompt(payload.prompt)
        thread = await get_or_create_thread(db, user, payload.thread_id, safe_prompt, payload.title)
        db.add(AIMessage(thread_id=thread.id, user_id=user.id, role="user", content=safe_prompt))
        await db.commit()

        response = await ai_service.generate_ai_response(payload.prompt, model=payload.model)
        if "error" in response:
            raise HTTPException(status_code=502, detail=response)
        if "model" in response and "model_used" not in response:
            response["model_used"] = response["model"]
        db.add(AIMessage(
            thread_id=thread.id,
            user_id=user.id,
            role="ai",
            content=response.get("answer") or "",
            model=response.get("model_used") or response.get("model")
        ))
        await db.commit()
        response["thread_id"] = thread.id
        return response
    except ai_service.PromptInjectionError as e:
        raise HTTPException(status_code=403, detail=str(e))

@router.delete("/threads/{thread_id}")
async def delete_thread(
    thread_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    result = await db.execute(select(AIThread).where(AIThread.id == thread_id, AIThread.user_id == user.id))
    thread = result.scalars().first()
    if not thread:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI thread not found")
    
    await db.execute(
        sa_delete(AIMessage).where(AIMessage.thread_id == thread_id)
    )
    await db.delete(thread)
    await db.commit()
    return {"status": "deleted", "thread_id": thread_id}
