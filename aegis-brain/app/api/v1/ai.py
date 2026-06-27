from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import get_current_user
from app.services import ai_service
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
        thread = await get_or_create_thread(db, user, payload.thread_id, payload.prompt, payload.title)
        db.add(AIMessage(thread_id=thread.id, user_id=user.id, role="user", content=payload.prompt))
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
