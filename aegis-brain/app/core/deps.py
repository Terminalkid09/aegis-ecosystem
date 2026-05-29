from fastapi import Header, HTTPException, status, Depends
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
from app.core.config import settings
from app.core.security import decode_access_token, is_token_blacklisted
from app.database.connection import get_db
from app.database.models import User
from sqlalchemy import select

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    expected_key = settings.AEGIS_API_KEY
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key not configured on server"
        )
    if x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing X-Api-Key"
        )
    return x_api_key

async def get_current_user(token: str = Header(..., alias="Authorization"), db: AsyncSession = Depends(get_db)):
    if token.startswith("Bearer "):
        token = token[7:]
    
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    jti = payload.get("jti")
    if await is_token_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    
    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user

async def get_optional_user(authorization: Optional[str] = Header(None), db: AsyncSession = Depends(get_db)):
    if not authorization:
        return None
    try:
        return await get_current_user(authorization, db)
    except HTTPException:
        return None
