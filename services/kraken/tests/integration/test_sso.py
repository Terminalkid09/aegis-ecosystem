import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.models import User

SECRET = "sso-test-secret-that-is-long-enough-123456"


def _assertion(username: str, *, audience: str = "kraken", jti: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "42",
            "username": username,
            "role": "admin",
            "iss": "aegis-brain",
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(seconds=60),
            "jti": jti or str(uuid.uuid4()),
        },
        SECRET,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_sso_exchange_creates_namespaced_user_and_session(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "KRAKEN_SSO_ENABLED", True)
    monkeypatch.setattr(settings, "KRAKEN_SSO_SECRET", SECRET)
    username = f"alice-{uuid.uuid4().hex[:8]}"

    response = await client.post("/api/v1/auth/sso", json={"token": _assertion(username)})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["access_token"]
    assert "kraken_token" in response.cookies

    row = (await db_session.execute(
        select(User).where(User.username == f"aegis:{username}")
    )).scalar_one()
    assert row.is_admin is True
    assert row.is_active is True


@pytest.mark.asyncio
async def test_sso_assertion_is_single_use(client, monkeypatch):
    monkeypatch.setattr(settings, "KRAKEN_SSO_ENABLED", True)
    monkeypatch.setattr(settings, "KRAKEN_SSO_SECRET", SECRET)
    token = _assertion(f"bob-{uuid.uuid4().hex[:8]}")

    first = await client.post("/api/v1/auth/sso", json={"token": token})
    second = await client.post("/api/v1/auth/sso", json={"token": token})
    assert first.status_code == 200
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_sso_rejects_wrong_audience(client, monkeypatch):
    monkeypatch.setattr(settings, "KRAKEN_SSO_ENABLED", True)
    monkeypatch.setattr(settings, "KRAKEN_SSO_SECRET", SECRET)
    response = await client.post(
        "/api/v1/auth/sso",
        json={"token": _assertion("mallory", audience="aegis-api")},
    )
    assert response.status_code == 401
