import jwt
import pytest
from fastapi import status

from app.core.config import settings


@pytest.mark.asyncio
async def test_overview_is_read_only_and_available(client, user_auth_headers):
    response = await client.get("/api/v1/deception/overview", headers=user_auth_headers)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["available"] is True
    assert body["kraken_ui"] == "/kraken/"
    assert set(body["stats"]) == {
        "events", "unique_source_ips", "deception_alerts",
        "open_deception_alerts", "incidents",
    }
    assert isinstance(body["events"], list)


@pytest.mark.asyncio
async def test_sso_token_requires_the_dedicated_secret(client, user_auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "KRAKEN_SSO_ENABLED", True)
    monkeypatch.setattr(settings, "KRAKEN_SSO_SECRET", "x" * 40)
    monkeypatch.setattr(settings, "KRAKEN_SSO_TTL_SECONDS", 30)

    response = await client.post("/api/v1/deception/token", headers=user_auth_headers)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["expires_in"] == 30
    assert body["sso_url"] == "/kraken/sso"

    claims = jwt.decode(
        body["token"],
        "x" * 40,
        algorithms=["HS256"],
        audience="kraken",
        issuer="aegis-brain",
    )
    assert claims["role"] == "user"
    assert claims["username"] == "testuser"
    assert claims["jti"]


@pytest.mark.asyncio
async def test_sso_token_is_refused_when_not_configured(client, user_auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "KRAKEN_SSO_ENABLED", False)
    monkeypatch.setattr(settings, "KRAKEN_SSO_SECRET", None)

    response = await client.post("/api/v1/deception/token", headers=user_auth_headers)
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
