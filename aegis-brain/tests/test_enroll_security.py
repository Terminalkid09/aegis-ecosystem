"""AEGIS-SEC-001: host-bound enrollment tokens, senza dipendere dal DB.

I test di integrazione in `tests/integration/test_enroll.py` coprono il flusso
HTTP completo quando Postgres è disponibile. Questi test bloccano la logica di
binding anche su una macchina senza database: un token senza target non è una
prova per ri-enrollare un host esistente.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.database.models import EnrollToken
from app.services.enrollment import consume_enroll_token, token_target_hostname, validate_enroll_token


class _Scalars:
    def __init__(self, token):
        self._token = token

    def first(self):
        return self._token


class _Result:
    def __init__(self, token):
        self._token = token

    def scalars(self):
        return _Scalars(self._token)


class _FakeDB:
    def __init__(self, token):
        self._token = token

    async def execute(self, _stmt):
        return _Result(self._token)


def _raw_token():
    return "host-bound-token"


def _token(*, target=None, used=None):
    config = {"dashboard_remote": True}
    if target:
        config["target_hostname"] = target
    return EnrollToken(
        token_hash=hashlib.sha256(_raw_token().encode()).hexdigest(),
        agent_type="nodetrace",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        install_config=config,
        used_agent_types=used or [],
    )


@pytest.mark.asyncio
async def test_host_bound_token_rejects_another_host():
    token = _token(target="host-a")
    with pytest.raises(HTTPException) as exc:
        await validate_enroll_token(_FakeDB(token), _raw_token(), "nodetrace", "host-b")
    assert exc.value.status_code == 403
    assert token_target_hostname(token) == "host-a"


@pytest.mark.asyncio
async def test_token_without_target_is_not_a_reenroll_proof():
    token = _token()
    # Il token resta valido per un primo enrollment, ma non ha un target da
    # usare come prova di possesso per un host già registrato.
    validated = await validate_enroll_token(
        _FakeDB(token), _raw_token(), "nodetrace", "host-a")
    assert validated is token
    assert token_target_hostname(validated) == ""


@pytest.mark.asyncio
async def test_consume_marks_token_used_for_agent_type():
    token = _token(target="host-a")
    consumed = await consume_enroll_token(
        _FakeDB(token), _raw_token(), "nodetrace", "host-a")
    assert consumed.used_agent_types == ["nodetrace"]
    assert consumed.used_by_hostname == "host-a"
    assert consumed.used_at is not None
