from datetime import datetime, timezone
import hashlib

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import EnrollToken


def token_target_hostname(token: EnrollToken | None) -> str:
    """Hostname legato al token, se l'operatore ne ha emesso uno per host."""
    config = token.install_config if token and isinstance(token.install_config, dict) else {}
    return str(config.get("target_hostname") or "").strip()


def _allowed_agent_types(token: EnrollToken) -> set[str]:
    if token.agent_type == "both":
        return {"aegis-guard", "nodetrace"}
    return {token.agent_type}


async def validate_enroll_token(
    db: AsyncSession,
    raw_token: str,
    agent_type: str,
    hostname: str,
    *,
    for_update: bool = False,
) -> EnrollToken:
    """Valida il token senza consumarlo.

    Il re-enroll deve poter verificare il binding all'host prima di bruciare il
    token; il consumo avviene solo dopo tutte le altre decisioni.
    """
    digest = hashlib.sha256((raw_token or "").strip().encode()).hexdigest()
    stmt = select(EnrollToken).where(EnrollToken.token_hash == digest)
    if for_update:
        stmt = stmt.with_for_update()
    result = await db.execute(stmt)
    token = result.scalars().first()
    now = datetime.now(timezone.utc)
    expires_at = token.expires_at.replace(tzinfo=timezone.utc) if token and token.expires_at else None
    if not token or token.revoked or not expires_at or expires_at <= now:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired enrollment token")

    if agent_type not in _allowed_agent_types(token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token agent type does not match enrollment")

    target = token_target_hostname(token)
    if target and target.casefold() != (hostname or "").strip().casefold():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Enrollment token is bound to host {target}",
        )

    used_types = set(token.used_agent_types or [])
    if agent_type in used_types:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enrollment token already used for this agent type")
    return token


async def consume_enroll_token(
    db: AsyncSession,
    raw_token: str,
    agent_type: str,
    hostname: str,
) -> EnrollToken:
    """Consume one agent slot from a short-lived enrollment token."""
    token = await validate_enroll_token(db, raw_token, agent_type, hostname, for_update=True)
    now = datetime.now(timezone.utc)
    used_types = set(token.used_agent_types or [])
    used_types.add(agent_type)
    token.used_agent_types = sorted(used_types)
    token.used_at = now if _allowed_agent_types(token).issubset(used_types) else None
    token.used_by_hostname = hostname[:255]
    return token
