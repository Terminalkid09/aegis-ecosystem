from datetime import datetime, timedelta, timezone
import uuid

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database.connection import get_db
from app.database.models import OSINTReport, User
from app.core.security import create_access_token, hash_password
from app.services import osint_service


@pytest.mark.asyncio
async def test_cached_ip_returned(monkeypatch, db_session):
    suffix = uuid.uuid4().hex
    user = User(
        username=f"n1-{suffix}",
        email=f"n1-{suffix}@test",
        password_hash=hash_password("pass"),
        role="user",
        active=True,
    )
    db_session.add(user)
    db_session.add(
        OSINTReport(
            query="1.1.1.1",
            source="ip",
            data={"cached": True},
            cached_until=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )
    await db_session.commit()
    await db_session.refresh(user)

    class MockAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            raise AssertionError("Should use cache")

    monkeypatch.setattr(osint_service.httpx, "AsyncClient", MockAsyncClient)
    token, _, _ = create_access_token(str(user.id), user.role)

    async def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {token}"}
        r = await client.get("/api/v1/osint/ip/1.1.1.1", headers=headers)

    app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json()["cached"] is True
