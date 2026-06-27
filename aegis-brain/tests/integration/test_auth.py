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
        response = await client.post("/api/v1/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "anypassword"
        })
        assert response.status_code == 401

    async def test_rate_limit_register(self, client: AsyncClient):
        for i in range(7):
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