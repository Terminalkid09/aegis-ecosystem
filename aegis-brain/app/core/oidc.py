"""Generic OpenID Connect helpers.

Deliberately provider-neutral: Entra ID, Okta, Keycloak and Authentik all speak
discovery + Authorization Code + PKCE + JWKS. SAML and SCIM are separate
protocols and are not pretending to be supported here.

Security properties:
- state, nonce and PKCE verifier live in a short-lived HttpOnly signed cookie,
  so no server-side session table is needed and multi-worker deployments work;
- the ID token signature is verified against the provider JWKS, with ``iss``,
  ``aud``, ``exp`` and ``nonce`` checked;
- only asymmetric algorithms are accepted (never ``none`` or HMAC);
- group names map to roles by an explicit operator-configured table.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt as pyjwt

from app.core.config import settings

STATE_ISSUER = "aegis-oidc"
STATE_AUDIENCE = "aegis-oidc-state"
STATE_TTL_S = 600
ALLOWED_ID_TOKEN_ALGS = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
}
ROLE_ORDER = ("admin", "analyst", "responder", "auditor", "user", "viewer")


class OIDCError(Exception):
    """A provider response or token failed validation."""


def enabled() -> bool:
    return bool(settings.OIDC_ENABLED)


def issuer() -> str:
    return (settings.OIDC_ISSUER or "").strip().rstrip("/")


def redirect_uri() -> str:
    configured = (settings.OIDC_REDIRECT_URI or "").strip()
    if configured:
        return configured
    return (settings.PUBLIC_BASE_URL or "").strip().rstrip("/") + "/api/v1/auth/oidc/callback"


def discovery_url() -> str:
    configured = (settings.OIDC_DISCOVERY_URL or "").strip()
    if configured:
        return configured
    return issuer() + "/.well-known/openid-configuration"


async def _get_json(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(
            timeout=settings.OIDC_HTTP_TIMEOUT_S,
            follow_redirects=False,
        ) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError("provider metadata request failed") from exc
    if not isinstance(data, dict):
        raise OIDCError("provider metadata is not an object")
    return data


async def discover() -> dict[str, Any]:
    data = await _get_json(discovery_url())
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise OIDCError(f"provider discovery is missing {key}")
    return data


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_nonce() -> str:
    return secrets.token_urlsafe(32)


def encode_state(*, state: str, verifier: str, nonce: str, return_to: str) -> str:
    now = int(time.time())
    payload = {
        "iss": STATE_ISSUER,
        "aud": STATE_AUDIENCE,
        "iat": now,
        "exp": now + STATE_TTL_S,
        "state": state,
        "verifier": verifier,
        "nonce": nonce,
        "return_to": safe_return_to(return_to),
    }
    return pyjwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_state(token: str | None) -> dict[str, Any]:
    if not token:
        raise OIDCError("missing OIDC state")
    try:
        payload = pyjwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            issuer=STATE_ISSUER,
            audience=STATE_AUDIENCE,
            leeway=30,
        )
    except pyjwt.PyJWTError as exc:
        raise OIDCError("invalid or expired OIDC state") from exc
    if not isinstance(payload.get("state"), str) or not isinstance(payload.get("verifier"), str):
        raise OIDCError("invalid OIDC state payload")
    return payload


def authorization_url(
    metadata: Mapping[str, Any],
    *,
    state: str,
    nonce: str,
    challenge: str,
    redirect: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": redirect,
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    endpoint = str(metadata["authorization_endpoint"])
    return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


async def exchange_code(
    metadata: Mapping[str, Any],
    *,
    code: str,
    verifier: str,
    redirect: str,
) -> dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "client_id": settings.OIDC_CLIENT_ID,
        "code_verifier": verifier,
    }
    secret = (settings.OIDC_CLIENT_SECRET or "").strip()
    if secret:
        data["client_secret"] = secret
    try:
        async with httpx.AsyncClient(
            timeout=settings.OIDC_HTTP_TIMEOUT_S,
            follow_redirects=False,
        ) as client:
            response = await client.post(
                str(metadata["token_endpoint"]),
                data=data,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError("token exchange failed") from exc
    if not isinstance(payload, dict):
        raise OIDCError("token endpoint response is not an object")
    return payload


async def fetch_userinfo(metadata: Mapping[str, Any], access_token: str) -> dict[str, Any]:
    endpoint = metadata.get("userinfo_endpoint")
    if not isinstance(endpoint, str) or not endpoint or not access_token:
        return {}
    try:
        async with httpx.AsyncClient(
            timeout=settings.OIDC_HTTP_TIMEOUT_S,
            follow_redirects=False,
        ) as client:
            response = await client.get(
                endpoint,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError("userinfo request failed") from exc
    if not isinstance(payload, dict):
        raise OIDCError("userinfo response is not an object")
    return payload


async def fetch_jwks(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return await _get_json(str(metadata["jwks_uri"]))


def _select_jwk(jwks: Mapping[str, Any], kid: str | None, alg: str) -> dict[str, Any]:
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise OIDCError("provider JWKS contains no keys")
    candidates = [key for key in keys if isinstance(key, dict)]
    if kid:
        candidates = [key for key in candidates if key.get("kid") == kid]
    candidates = [key for key in candidates if not key.get("alg") or key.get("alg") == alg]
    if len(candidates) != 1:
        raise OIDCError("no unique signing key for ID token")
    return candidates[0]


def validate_id_token(
    token: str,
    jwks: Mapping[str, Any],
    *,
    nonce: str,
) -> dict[str, Any]:
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise OIDCError("invalid ID token header") from exc

    alg = header.get("alg")
    if alg not in ALLOWED_ID_TOKEN_ALGS:
        raise OIDCError("ID token uses an unsupported algorithm")
    jwk = _select_jwk(jwks, header.get("kid"), str(alg))
    try:
        key = pyjwt.PyJWK(jwk).key
        claims = pyjwt.decode(
            token,
            key=key,
            algorithms=[str(alg)],
            audience=settings.OIDC_CLIENT_ID,
            issuer=issuer(),
            leeway=settings.OIDC_CLOCK_SKEW_S,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except (pyjwt.PyJWTError, ValueError) as exc:
        raise OIDCError("ID token validation failed") from exc

    if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"], nonce):
        raise OIDCError("ID token nonce mismatch")
    return claims


def group_role_map() -> dict[str, str]:
    raw = (settings.OIDC_GROUP_ROLE_MAP or "{}").strip() or "{}"
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise OIDCError("OIDC_GROUP_ROLE_MAP must be a JSON object")
    return {str(k): str(v).lower() for k, v in data.items()}


def groups_from_claims(claims: Mapping[str, Any]) -> list[str]:
    value = claims.get(settings.OIDC_GROUPS_CLAIM or "groups")
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def role_from_groups(groups: list[str], mapping: Mapping[str, str] | None = None) -> str:
    """Pick the highest-privilege matching role; never an unknown role."""
    table = dict(mapping or group_role_map())
    folded = {key.casefold(): value for key, value in table.items()}
    matched = set()
    for group in groups:
        role = table.get(group) or folded.get(group.casefold())
        if role:
            matched.add(role)
    for role in ROLE_ORDER:
        if role in matched:
            return role
    default = (settings.OIDC_DEFAULT_ROLE or "viewer").lower().strip()
    return default if default in ROLE_ORDER else "viewer"


def email_verified(claims: Mapping[str, Any]) -> bool:
    value = claims.get("email_verified")
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}


def username_from_claims(claims: Mapping[str, Any]) -> str:
    preferred = str(claims.get("preferred_username") or "").strip()
    email = str(claims.get("email") or "").strip()
    base = preferred or email.split("@", 1)[0]
    base = re.sub(r"[^A-Za-z0-9._-]+", ".", base).strip("._-")[:150]
    if len(base) < 3:
        base = "sso-user-" + hashlib.sha256(email.encode("utf-8")).hexdigest()[:8]
    return base


def safe_return_to(value: str | None) -> str:
    candidate = (value or "/").strip()
    if not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate:
        return "/"
    return candidate


def frontend_url(value: str | None) -> str:
    """Build the post-callback URL on the public SPA origin.

    The callback is served by the Brain, while the user starts on the frontend
    (for example :3000 in a local install). Redirecting to a relative path from
    /api/v1/auth/oidc/callback lands on the Brain root, not on the dashboard.
    PUBLIC_BASE_URL is the externally reachable frontend/Caddy origin.
    """
    path = safe_return_to(value)
    base = (settings.PUBLIC_BASE_URL or "").strip().rstrip("/")
    return base + path if base else path
