from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from app.database.connection import get_db
from app.database.models import Agent
from app.core.security import verify_password
from sqlalchemy import select

async def get_current_agent(
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_db)
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")
    
    token = authorization[7:]
    
    try:
        agent_id_uuid = uuid.UUID(x_agent_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Agent ID format")
    
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id_uuid))
    agent = result.scalars().first()
    
    if not agent or not agent.device_token_hash:
        raise HTTPException(status_code=401, detail="Agent not found or not registered")
    
    if not verify_password(token, agent.device_token_hash):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")
    
    return agent
