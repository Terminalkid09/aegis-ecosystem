from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import User
from app.core.security import hash_password, verify_password, needs_rehash, create_access_token
from app.api.schemas.common import TokenResponse, UserOut
from pydantic import BaseModel

router = APIRouter(tags=["Authentication"])

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

@router.post("/register", response_model=TokenResponse)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password)
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    return {"access_token": token, "token_type": "bearer", "user": user}

@router.post("/login", response_model=TokenResponse)
async def login(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()
    
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        await db.commit()
        
    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    return {"access_token": token, "token_type": "bearer", "user": user}
