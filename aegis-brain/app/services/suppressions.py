"""Governed suppression matching and validation.

When a row matches, the caller skips the alert and the row increments its
counter. The rule itself remains enabled; the weekly review can see exactly
how many detections were hidden and when the suppression expires.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.database.models import Suppression

logger = get_logger(__name__)

MAX_TTL_DAYS = 90
MIN_TTL_SECONDS = 60


def normalize_expiry(expires_at: datetime, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    delta = expires_at - now
    if delta.total_seconds() < MIN_TTL_SECONDS:
        raise ValueError("expires_at must be at least 60 seconds in the future")
    if delta > timedelta(days=MAX_TTL_DAYS):
        raise ValueError(f"expires_at cannot exceed {MAX_TTL_DAYS} days")
    return expires_at


def _matches(scope: Dict[str, Any], event: Any) -> bool:
    for key, expected in scope.items():
        actual = getattr(event, key, None)
        if isinstance(expected, (list, tuple, set)):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


async def find_matching_suppression(
    db: AsyncSession, rule_id: str, event: Any,
    now: Optional[datetime] = None,
) -> Optional[Suppression]:
    now = now or datetime.now(timezone.utc)
    rows = (await db.execute(
        select(Suppression).where(
            Suppression.rule_id == rule_id,
            Suppression.active.is_(True),
            Suppression.expires_at > now,
        )
    )).scalars().all()
    for row in rows:
        scope = row.scope if isinstance(row.scope, dict) else {}
        if _matches(scope, event):
            row.suppressed_count = int(row.suppressed_count or 0) + 1
            row.last_suppressed_at = now
            await db.flush()
            return row
    return None


async def is_suppressed(db: AsyncSession, rule_id: str, event: Any) -> bool:
    try:
        return await find_matching_suppression(db, rule_id, event) is not None
    except Exception as exc:
        # Hiding an alert because the suppression table is broken would turn a
        # governance feature into a detection bypass. Fail open to visibility.
        logger.warning("Suppression lookup failed for %s: %s", rule_id, exc)
        # Never roll back the caller's transaction: it also contains the
        # SIEM event that was just stored. Visibility is the safe fallback.
        return False
