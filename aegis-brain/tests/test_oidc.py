"""OIDC helpers: group mapping, signed state, public policy endpoints."""
import pytest

from app.core import oidc
from app.core.config import settings


def test_role_mapping_uses_highest_privilege(monkeypatch):
    monkeypatch.setattr(
        settings, "OIDC_GROUP_ROLE_MAP",
        '{"aegis-viewers":"viewer","aegis-analysts":"analyst","aegis-admins":"admin"}',
        raising=False,
    )
    monkeypatch.setattr(settings, "OIDC_DEFAULT_ROLE", "viewer", raising=False)
    assert oidc.role_from_groups(["aegis-viewers", "aegis-analysts"]) == "analyst"
    assert oidc.role_from_groups(["aegis-analysts", "aegis-admins"]) == "admin"
    assert oidc.role_from_groups([]) == "viewer"


def test_role_mapping_is_case_tolerant_and_never_unknown(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_GROUP_ROLE_MAP",
                        '{"Aegis-Admins":"admin"}', raising=False)
    monkeypatch.setattr(settings, "OIDC_DEFAULT_ROLE", "viewer", raising=False)
    assert oidc.role_from_groups(["aegis-admins"]) == "admin"
    assert oidc.role_from_groups(["unknown-group"]) == "viewer"


def test_frontend_url_keeps_brain_redirect_off_the_api_root(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "https://aegis.example", raising=False)
    assert oidc.frontend_url("/") == "https://aegis.example/"
    assert oidc.frontend_url("/alerts?x=1") == "https://aegis.example/alerts?x=1"
    assert oidc.frontend_url("//evil.example") == "https://aegis.example/"


def test_state_roundtrip_and_safe_return(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET", "x" * 40, raising=False)
    token = oidc.encode_state(
        state="state-1", verifier="verifier-1", nonce="nonce-1",
        return_to="//evil.example/path",
    )
    payload = oidc.decode_state(token)
    assert payload["state"] == "state-1"
    assert payload["verifier"] == "verifier-1"
    assert payload["return_to"] == "/"
    assert oidc.safe_return_to("/alerts?x=1") == "/alerts?x=1"
    assert oidc.safe_return_to("https://evil.example") == "/"
    assert oidc.safe_return_to("/\\evil") == "/"


@pytest.mark.asyncio
async def test_oidc_config_is_public_and_fail_closed(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ENABLED", False, raising=False)
    response = await client.get("/api/v1/auth/oidc/config")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["login_url"] == "/api/v1/auth/oidc/login"


@pytest.mark.asyncio
async def test_oidc_login_is_404_when_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ENABLED", False, raising=False)
    response = await client.get("/api/v1/auth/oidc/login")
    assert response.status_code == 404
