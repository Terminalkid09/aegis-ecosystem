import pytest
from httpx import AsyncClient


class TestAuth:
    async def test_register_success(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/register", json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "securepass123"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["username"] == "newuser"
        assert data["user"]["email"] == "new@example.com"
        assert "access_token" in data

    async def test_register_duplicate_email(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/register", json={
            "username": "another",
            "email": test_user.email,
            "password": "password123"
        })
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    async def test_register_validation_rejects(self, client: AsyncClient):
        # Audit: password corta, email malformata, username fuori policy.
        for payload in (
            {"username": "u1", "email": "a@b.co", "password": "short"},
            {"username": "validuser", "email": "not-an-email", "password": "password123"},
            {"username": "bad user!", "email": "x@y.zz", "password": "password123"},
        ):
            response = await client.post("/api/v1/auth/register", json=payload)
            assert response.status_code == 422, payload

    async def test_register_closed_when_disabled(self, client: AsyncClient, monkeypatch):
        # Audit: ALLOW_OPEN_REGISTRATION=false -> solo admin.
        from app.core.config import settings
        monkeypatch.setattr(settings, "ALLOW_OPEN_REGISTRATION", False)
        response = await client.post("/api/v1/auth/register", json={
            "username": "newuser2",
            "email": "new2@example.com",
            "password": "securepass123"
        })
        assert response.status_code == 403

    async def test_login_success(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "testpass123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_invalid_credentials(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        import uuid as _uuid
        # Email unica per run: il throttle anti-brute-force conta i fallimenti
        # per email su Redis condiviso (niente flaky tra run consecutivi).
        response = await client.post("/api/v1/auth/login", json={
            "email": f"nonexistent-{_uuid.uuid4().hex[:8]}@example.com",
            "password": "anypassword"
        })
        assert response.status_code == 401

    async def test_rate_limit_register(self, client: AsyncClient):
        for i in range(7):
            # Cookie jar pulito a ogni tentativo: il cookie auth dei tentativi
            # riusciti attiverebbe il CSRF-check (403) e non testeremmo il rate
            # limit (429). I browser reali inviano Origin, httpx no.
            client.cookies.clear()
            response = await client.post("/api/v1/auth/register", json={
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "password": "password123"
            })
            if response.status_code == 429:
                break
        assert response.status_code == 429

    async def test_rate_limit_login(self, client: AsyncClient):
        for _ in range(12):
            response = await client.post("/api/v1/auth/login", json={
                "email": "nonexistent@example.com",
                "password": "wrong"
            })
            if response.status_code == 429:
                break
        assert response.status_code == 429