from datetime import datetime, timezone
import hashlib

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import EnrollToken


async def consume_enroll_token(
    db: AsyncSession,
    raw_token: str,
    agent_type: str,
    hostname: str,
) -> EnrollToken:
    """Consume one agent slot from a short-lived enrollment token."""
    digest = hashlib.sha256((raw_token or "").strip().encode()).hexdigest()
    result = await db.execute(
        select(EnrollToken).where(EnrollToken.token_hash == digest).with_for_update()
    )
    token = result.scalars().first()
    now = datetime.now(timezone.utc)
    expires_at = token.expires_at.replace(tzinfo=timezone.utc) if token and token.expires_at else None
    if not token or token.revoked or not expires_at or expires_at <= now:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired enrollment token")

    allowed = {agent_type} if token.agent_type != "both" else {"aegis-guard", "nodetrace"}
    if agent_type not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token agent type does not match enrollment")

    used_types = set(token.used_agent_types or [])
    if agent_type in used_types:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enrollment token already used for this agent type")

    used_types.add(agent_type)
    token.used_agent_types = sorted(used_types)
    token.used_at = now if allowed.issubset(used_types) else None
    token.used_by_hostname = hostname[:255]
    return token
