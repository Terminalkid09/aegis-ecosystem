"""API key di ingestione: hash, scopes, sorgente e revoca.

La chiave globale `AEGIS_API_KEY` resta supportata per compatibilita', ma le
integrazioni possono ora avere una chiave dedicata. La chiave in chiaro non
viene mai salvata: in DB c'e' solo SHA-256, e viene mostrata una volta alla
creazione. La revoca e' un filtro sulla query, quindi ha effetto immediato.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select

from app.core.config import settings
from app.database.models import APIKey


def generate_api_key() -> str:
    """Chiave con entropia da 256 bit, prefisso riconoscibile nei log."""
    return "aegis_" + secrets.token_urlsafe(32)


def hash_api_key(raw: str) -> str:
    """Hash deterministico per lookup; la chiave ha gia' entropia sufficiente."""
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


def source_allowed(auth: Dict[str, Any], source: str) -> bool:
    """Una chiave limitata puo' scrivere solo sulla propria sorgente."""
    restricted = (auth or {}).get("source")
    return not restricted or str(restricted) == str(source)


def _global_key(raw: str) -> Optional[Dict[str, Any]]:
    expected = settings.AEGIS_API_KEY
    if expected and hmac.compare_digest(raw, expected):
        return {
            "kind": "api_key", "id": None, "name": "global", "username": "api-key",
            "source": None, "scopes": {"scopes": ["*"]}, "global": True,
        }
    return None


async def resolve_api_key(db, raw: Optional[str]) -> Optional[Dict[str, Any]]:
    """Risolve la chiave globale o una chiave DB attiva/non revocata."""
    if not raw:
        return None
    raw = raw.strip()
    global_auth = _global_key(raw)
    if global_auth is not None:
        return global_auth

    result = await db.execute(
        select(APIKey).where(
            APIKey.hashed_key == hash_api_key(raw),
            APIKey.active.is_(True),
            APIKey.revoked_at.is_(None),
        )
    )
    key = result.scalars().first()
    if key is None:
        return None
    key.last_used = datetime.now(timezone.utc)
    return {
        "kind": "api_key",
        "id": key.id,
        "name": key.name or f"key-{key.id}",
        "username": "api-key",
        "source": key.source,
        "scopes": key.scopes or {},
        "global": False,
    }
