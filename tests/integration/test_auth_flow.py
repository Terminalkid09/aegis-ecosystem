from httpx import AsyncClient

from app.core.config import settings


class TestAuthFlow:
    async def test_register_success(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True)
        response = await client.post("/api/v1/auth/register", json={
            "username": "newuser",
            "password": "securepass123",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["is_admin"] is False
        assert "id" in data

    async def test_register_duplicate_username(self, client: AsyncClient, test_user, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True)
        response = await client.post("/api/v1/auth/register", json={
            "username": test_user.username,
            "password": "anotherpass123",
        })
        assert response.status_code == 400
        assert "already taken" in response.json()["detail"]

    async def test_register_disabled_by_default(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_REGISTRATION", False)
        response = await client.post("/api/v1/auth/register", json={
            "username": "closeduser",
            "password": "securepass123",
        })
        assert response.status_code == 403

    async def test_register_rejects_is_admin(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True)
        response = await client.post("/api/v1/auth/register", json={
            "username": "wannabeadmin",
            "password": "securepass123",
            "is_admin": True,
        })
        assert response.status_code == 422

    async def test_login_success(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "kraken_token" in response.cookies

    async def test_login_invalid_credentials(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "anypassword"
        })
        assert response.status_code == 401

    async def test_refresh_token_is_single_use(self, client: AsyncClient, test_user):
        login = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123",
        })
        refresh_token = login.json()["refresh_token"]
        first = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert first.status_code == 200
        second = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert second.status_code == 401

    async def test_logout_revokes_refresh_cookie(self, client: AsyncClient, test_user):
        login = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123",
        })
        refresh_token = login.json()["refresh_token"]
        # The cookie is Secure; httpx does not send it over the test http URL.
        logout = await client.post(
            "/api/v1/auth/logout",
            cookies={"kraken_refresh": refresh_token},
        )
        assert logout.status_code == 204
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert response.status_code == 401

    async def test_cookie_auth_on_protected_route(self, client: AsyncClient, test_user):
        login_resp = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123"
        })
        assert login_resp.status_code == 200
        cookie = login_resp.cookies.get("kraken_token")
        assert cookie is not None

        client.cookies.set("kraken_token", cookie)
        response = await client.get("/api/v1/events/")
        assert response.status_code == 200

    async def test_bearer_token_auth_on_protected_route(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/events/", headers=auth_headers)
        assert response.status_code == 200

    async def test_unauthorized_without_token(self, client: AsyncClient):
        response = await client.get("/api/v1/events/")
        assert response.status_code == 401

    async def test_rate_limit_on_login(self, client: AsyncClient):
        for _ in range(12):
            await client.post("/api/v1/auth/login", json={
                "username": "nonexistent",
                "password": "wrong"
            })
        response = await client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "wrong"
        })
        assert response.status_code == 429