"""SSO-only policy: the server enforces OIDC_ALLOW_LOCAL_LOGIN, not just the UI."""
import pytest

from app.core.config import settings

pytestmark = pytest.mark.asyncio


async def test_unknown_email_returns_generic_401(client):
    r = await client.post("/api/v1/auth/login", json={
        "email": "nobody@aegis.test", "password": "not-the-password",
    })
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"


async def test_sso_only_blocks_local_password_login(client, test_user, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_ALLOW_LOCAL_LOGIN", False, raising=False)

    r = await client.post("/api/v1/auth/login", json={
        "email": test_user.email, "password": "testpass123",
    })
    assert r.status_code == 403, r.text
    assert "SSO" in r.json()["detail"]


async def test_local_login_remains_available_when_oidc_is_disabled(client, test_user, monkeypatch):
    # A stale OIDC_ALLOW_LOCAL_LOGIN=false must not lock out a non-OIDC install.
    monkeypatch.setattr(settings, "OIDC_ENABLED", False, raising=False)
    monkeypatch.setattr(settings, "OIDC_ALLOW_LOCAL_LOGIN", False, raising=False)

    r = await client.post("/api/v1/auth/login", json={
        "email": test_user.email, "password": "testpass123",
    })
    assert r.status_code == 200, r.text
    assert r.headers.get("cache-control") == "no-store"


async def test_sso_only_blocks_local_registration(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_ALLOW_LOCAL_LOGIN", False, raising=False)
    monkeypatch.setattr(settings, "ALLOW_OPEN_REGISTRATION", True, raising=False)

    r = await client.post("/api/v1/auth/register", json={
        "username": "ssoonly", "email": "ssoonly@aegis.test",
        "password": "Str0ngPass!x",
    })
    assert r.status_code == 403, r.text


async def test_oidc_config_keeps_local_login_when_oidc_is_off(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ALLOW_LOCAL_LOGIN", False, raising=False)
    monkeypatch.setattr(settings, "OIDC_ENABLED", False, raising=False)
    r = await client.get("/api/v1/auth/oidc/config")
    assert r.status_code == 200
    assert r.json()["local_login"] is True

    monkeypatch.setattr(settings, "OIDC_ENABLED", True, raising=False)
    r = await client.get("/api/v1/auth/oidc/config")
    assert r.status_code == 200
    assert r.json()["local_login"] is False
