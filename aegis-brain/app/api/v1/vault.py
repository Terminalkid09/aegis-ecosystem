from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.database.connection import get_db
from app.database.models import Note, User
from app.core.deps import get_current_user
from app.core.crypto import encrypt_for_user, decrypt_for_user, generate_dek, encrypt_dek_with_kek
from app.api.schemas.common import NoteCreate, NoteOut

router = APIRouter(tags=["VaultX"])

@router.post("/notes", response_model=NoteOut)
async def create_note(payload: NoteCreate, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.encrypted_dek:
        dek = generate_dek()
        user.encrypted_dek = encrypt_dek_with_kek(dek)
        db.add(user)

    encrypted_content = encrypt_for_user(user.encrypted_dek, payload.content)
    note = Note(
        user_id=user.id,
        title=payload.title,
        content=encrypted_content,
        mood=payload.mood,
        tags=payload.tags
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    
    return NoteOut(
        id=note.id,
        title=note.title,
        content=payload.content,
        mood=note.mood,
        tags=note.tags
    )

@router.get("/notes", response_model=List[NoteOut])
async def get_notes(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    stmt = select(Note).where(Note.user_id == user.id).order_by(Note.created_at.desc())
    result = await db.execute(stmt)
    notes = result.scalars().all()
    
    out = []
    for n in notes:
        try:
            plaintext = decrypt_for_user(user.encrypted_dek, n.content)
        except Exception:
            plaintext = "[decryption_error]"
        out.append(NoteOut(id=n.id, title=n.title, content=plaintext, mood=n.mood, tags=n.tags))
    return out

@router.delete("/notes/{note_id}")
async def delete_note(note_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    note = await db.get(Note, note_id)
    if not note or note.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    await db.delete(note)
    await db.commit()
    return {"status": "deleted"}
