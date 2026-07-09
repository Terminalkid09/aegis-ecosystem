from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.connection import get_db
from app.database.models import Agent
from app.core.config import settings
from app.core.security import hash_password
from app.core.logging import get_logger
from app.core.redis_utils import get_redis_url
import redis.asyncio as redis
import uuid
import secrets
from pydantic import BaseModel

logger = get_logger(__name__)
router = APIRouter(tags=["Agent Enrollment"])

class EnrollRequest(BaseModel):
    hostname: str
    os: str
    enroll_key: str

class EnrollResponse(BaseModel):
    agent_id: str
    agent_secret: str
    status: str

@router.post("/enroll", response_model=EnrollResponse)
async def enroll_agent(payload: EnrollRequest, db: AsyncSession = Depends(get_db)):
    if payload.enroll_key.strip() != settings.AGENT_ENROLL_KEY:
        logger.warning(f"Invalid enrollment attempt from {payload.hostname}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid enrollment key")

    agent_id = uuid.uuid4()
    agent_secret = secrets.token_urlsafe(32)

    # Check if agent with same hostname+os already exists (race-safe via unique constraint)
    result = await db.execute(
        select(Agent).where(
            Agent.hostname == payload.hostname,
            Agent.os_type == payload.os
        )
    )
    existing = result.scalars().first()
    if existing:
        # Re-enroll: issue a fresh secret so agent can authenticate again
        new_secret = secrets.token_urlsafe(32)
        existing.device_token_hash = hash_password(new_secret)
        await db.commit()

        # Update Redis cache
        redis_client = redis.from_url(get_redis_url(), decode_responses=True)
        await redis_client.set(f"auth:agent:{new_secret}", str(existing.agent_id))

        logger.info(f"Agent re-enrolled: {existing.agent_id} ({payload.hostname})")
        return EnrollResponse(
            agent_id=str(existing.agent_id),
            agent_secret=new_secret,
            status="re-enrolled"
        )
    
    new_agent = Agent(
        agent_id=agent_id,
        hostname=payload.hostname,
        os_type=payload.os,
        agent_type="aegis-guard",
        device_token_hash=hash_password(agent_secret)
    )
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)
    
    # Cache in Redis for fast validation
    redis_client = redis.from_url(get_redis_url(), decode_responses=True)
    cache_key = f"auth:agent:{agent_secret}"
    await redis_client.set(cache_key, str(agent_id))
    
    logger.info(f"New agent enrolled: {agent_id} ({payload.hostname})")
    
    return EnrollResponse(
        agent_id=str(agent_id),
        agent_secret=agent_secret,
        status="enrolled"
    )
