"""OIDC callback and ID-token validation with a locally generated RSA JWKS."""
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.core import oidc
from app.core.config import settings
from app.database.models import User


@pytest.fixture(scope="module")
def rsa_signer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    return key, {"keys": [jwk]}


def _claims(*, nonce="nonce-1", aud="client-1", iss="https://idp.example"):
    now = int(time.time())
    return {
        "iss": iss, "aud": aud, "sub": "subject-1",
        "email": "sso@example.test", "email_verified": True,
        "iat": now, "exp": now + 300, "nonce": nonce,
    }


def _token(signer, claims, *, kid="test-key", algorithm="RS256", key=None):
    headers = {"kid": kid} if kid else None
    return pyjwt.encode(claims, key or signer, algorithm=algorithm, headers=headers)


def test_id_token_accepts_valid_signature_and_nonce(rsa_signer, monkeypatch):
    signer, jwks = rsa_signer
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1", raising=False)
    token = _token(signer, _claims())
    assert oidc.validate_id_token(token, jwks, nonce="nonce-1")["sub"] == "subject-1"


@pytest.mark.parametrize("nonce", ["wrong", ""])
def test_id_token_rejects_bad_nonce(rsa_signer, monkeypatch, nonce):
    signer, jwks = rsa_signer
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1", raising=False)
    token = _token(signer, _claims())
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(token, jwks, nonce=nonce)


@pytest.mark.parametrize("claim,value", [
    ("aud", "another-client"),
    ("iss", "https://evil.example"),
])
def test_id_token_rejects_wrong_audience_or_issuer(rsa_signer, monkeypatch, claim, value):
    signer, jwks = rsa_signer
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1", raising=False)
    token = _token(signer, _claims(**{claim: value}))
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(token, jwks, nonce="nonce-1")


def test_id_token_rejects_none_hmac_and_unknown_kid(rsa_signer, monkeypatch):
    signer, jwks = rsa_signer
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1", raising=False)
    claims = _claims()

    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(_token(None, claims, algorithm="none", key=None), jwks,
                               nonce="nonce-1")
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(_token("shared-secret", claims, algorithm="HS256"), jwks,
                               nonce="nonce-1")
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(_token(signer, claims, kid="unknown"), jwks,
                               nonce="nonce-1")


@pytest.mark.asyncio
async def test_oidc_callback_creates_session_with_mocked_provider(client, db_session, monkeypatch):
    from sqlalchemy import select

    monkeypatch.setattr(settings, "OIDC_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1", raising=False)
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "https://aegis.test", raising=False)
    monkeypatch.setattr(settings, "OIDC_AUTO_CREATE_USERS", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_LINK_BY_EMAIL", False, raising=False)
    monkeypatch.setattr(settings, "OIDC_REQUIRE_VERIFIED_EMAIL", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_DEFAULT_ROLE", "viewer", raising=False)

    state = "state-ok"
    nonce = "nonce-ok"
    cookie = oidc.encode_state(
        state=state, verifier="verifier-ok", nonce=nonce, return_to="/")
    client.cookies.set("aegis_oidc_state", cookie, path="/api/v1/auth/oidc")

    async def fake_discover():
        return {"authorization_endpoint": "https://idp.example/auth",
                "token_endpoint": "https://idp.example/token",
                "jwks_uri": "https://idp.example/jwks",
                "userinfo_endpoint": "https://idp.example/userinfo"}

    async def fake_exchange(*args, **kwargs):
        return {"id_token": "signed", "access_token": "access"}

    async def fake_jwks(*args, **kwargs):
        return {"keys": []}

    async def fake_userinfo(*args, **kwargs):
        return {}

    def fake_validate(token, jwks, *, nonce):
        return _claims(nonce=nonce)

    monkeypatch.setattr(oidc, "discover", fake_discover)
    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)
    monkeypatch.setattr(oidc, "fetch_jwks", fake_jwks)
    monkeypatch.setattr(oidc, "fetch_userinfo", fake_userinfo)
    monkeypatch.setattr(oidc, "validate_id_token", fake_validate)

    response = await client.get(
        f"/api/v1/auth/oidc/callback?code=ok&state={state}", follow_redirects=False)
    assert response.status_code == 302, response.text
    assert response.headers["location"].startswith("https://aegis.test/")
    assert response.cookies.get("aegis_token")

    user = (await db_session.execute(
        select(User).where(User.email == "sso@example.test"))).scalars().first()
    assert user is not None
    assert user.role == "viewer"
    assert user.oidc_subject == "subject-1"
