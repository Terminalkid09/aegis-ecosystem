import os
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import AuditLog
from typing import Optional, Dict, Any

async def log_audit(
    db: AsyncSession,
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    is_test: Optional[bool] = None,
):
    # Isolamento test tenant (Fase 6+): solo flag esplicito o env non controllabili
    # dal client normale. Un utente reale "testuser" resta production.
    if is_test is None:
        is_test = (
            os.getenv("AEGIS_TENANT", "").lower() == "test"
            or os.getenv("PYTEST_CURRENT_TEST", "") != ""
        )
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=str(resource_id) if resource_id else None,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        is_test=bool(is_test),
    )
    db.add(entry)
