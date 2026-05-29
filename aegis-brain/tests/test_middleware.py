import pytest
from fastapi import HTTPException
from httpx import AsyncClient, ASGITransport

from app.core.config import settings
from app.core.deps import verify_api_key
from app.main import app


TEST_API_KEY = "test-secret-key"


def test_verify_api_key_missing(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_API_KEY", TEST_API_KEY)
    with pytest.raises(HTTPException) as exc:
        verify_api_key(None)

    assert exc.value.status_code == 403
    assert "Forbidden" in exc.value.detail


def test_verify_api_key_invalid(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_API_KEY", TEST_API_KEY)
    with pytest.raises(HTTPException) as exc:
        verify_api_key("wrong-key")

    assert exc.value.status_code == 403
    assert "Forbidden" in exc.value.detail


def test_verify_api_key_valid(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_API_KEY", TEST_API_KEY)
    assert verify_api_key(TEST_API_KEY) == TEST_API_KEY


def test_api_key_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_API_KEY", None)
    with pytest.raises(HTTPException) as exc:
        verify_api_key(TEST_API_KEY)

    assert exc.value.status_code == 500
    assert "API Key not configured" in exc.value.detail


@pytest.mark.asyncio
async def test_health_no_auth_required():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
