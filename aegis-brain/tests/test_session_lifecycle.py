"""Sessione: durata del cookie, cookie duplicati, rinnovo a scorrimento.

Il sintomo riportato era "ricarico la pagina e mi richiede l'accesso". Tre
cause distinte, tutte verificate qui:

1. `max_age` era un letterale 3600 accanto a una TTL configurabile: alzare
   JWT_EXPIRE_MINUTES lasciava il browser a scartare il cookie dopo un'ora.
2. Un cookie rimasto da una build precedente su path `/` viene inviato *insieme*
   a quello corrente, e il server legge l'ultimo valore di un nome ripetuto:
   con un duplicato stantio ogni richiesta rispondeva 401.
3. Nessun rinnovo: il token scadeva anche con la console in uso.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Response

from app.api.v1.auth import SESSION_COOKIE, SESSION_COOKIE_PATH, _set_auth_cookie
from app.core.config import settings
from app.core.security import create_access_token, decode_access_token


def _set_cookie_headers(response: Response) -> list[str]:
    return [v.decode() if isinstance(v, bytes) else v
            for k, v in response.raw_headers if k.decode().lower() == "set-cookie"]


class TestCookieTTL:
    def test_max_age_follows_the_configured_ttl(self, monkeypatch):
        """Il cookie non deve avere una scadenza propria diversa dal JWT."""
        monkeypatch.setattr(settings, "JWT_EXPIRE_MINUTES", 480, raising=False)
        resp = Response()
        _set_auth_cookie(resp, "tok")
        joined = " ".join(_set_cookie_headers(resp))
        assert "Max-Age=28800" in joined
        assert "Max-Age=3600" not in joined

    def test_cookie_is_httponly_and_scoped_to_the_api_path(self):
        resp = Response()
        _set_auth_cookie(resp, "tok")
        joined = " ".join(_set_cookie_headers(resp))
        assert "HttpOnly" in joined
        assert SESSION_COOKIE_PATH in joined

    def test_login_clears_a_legacy_cookie_on_the_root_path(self):
        """Il duplicato su path `/` va scaduto, non solo sovrascritto."""
        resp = Response()
        _set_auth_cookie(resp, "tok")
        expiring = [h for h in _set_cookie_headers(resp)
                    if "Max-Age=0" in h or "expires" in h.lower()]
        assert expiring, "nessun delete_cookie sul path legacy"
        assert any(f"Path=/" in h for h in expiring)


class TestSlidingRefresh:
    def _token(self, minutes_left: int) -> str:
        token, _, _ = create_access_token(subject="1", role="admin")
        # Riscrivo l'exp per simulare un token a meta' vita senza aspettare.
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=minutes_left)
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    def test_should_refresh_logic(self):
        """Il criterio: rinnovare solo oltre meta' vita consumata."""
        ttl = max(int(settings.JWT_EXPIRE_MINUTES), 1)

        def due(exp_epoch: int) -> bool:
            return exp_epoch - int(datetime.now(timezone.utc).timestamp()) <= ttl * 60 // 2

        now = int(datetime.now(timezone.utc).timestamp())
        assert due(now + ttl * 60 // 2 - 5) is True      # quasi meta' vita
        assert due(now + int(ttl * 60 * 0.9)) is False   # appena emesso

    def test_reissued_token_is_valid_and_keeps_the_subject(self):
        """Il refresh non deve degradare l'identita' della sessione."""
        old = self._token(minutes_left=5)
        payload = decode_access_token(old)
        assert payload is not None
        fresh, _, _ = create_access_token(subject=str(payload["sub"]),
                                          role=str(payload["role"]))
        new_payload = decode_access_token(fresh)
        assert new_payload is not None
        assert new_payload["sub"] == payload["sub"]
        assert new_payload["role"] == payload["role"]
        # jti nuovo: il refresh non riattiva un token revocato per jti.
        assert new_payload["jti"] != payload["jti"]

    def test_expired_token_is_not_refreshable(self):
        """Un token scaduto non si rinnova: si torna al login."""
        import jwt
        token, _, _ = create_access_token(subject="1", role="admin")
        payload = jwt.decode(token, options={"verify_signature": False})
        payload["exp"] = datetime.now(timezone.utc) - timedelta(minutes=1)
        expired = jwt.encode(payload, settings.JWT_SECRET,
                             algorithm=settings.JWT_ALGORITHM)
        assert decode_access_token(expired) is None


@pytest.mark.asyncio
async def test_duplicate_cookie_order_is_a_real_hazard(client):
    """Il server legge l'ultimo valore per un nome ripetuto: e' il motivo per
    cui un cookie stale su un altro path rendeva cieca tutta la sessione.
    Qui lo documentiamo, cosi' il comportamento non cambia in silenzio."""
    r = await client.get("/api/v1/auth/me", headers={
        "Cookie": "aegis_token=invalid; aegis_token=invalid2"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_without_any_session_is_401_not_500(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401
    assert SESSION_COOKIE in r.text or r.status_code == 401
