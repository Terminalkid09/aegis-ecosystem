"""Audit F-01/F-03: validator di configurazione fail-closed (puri, niente DB)."""
import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _prod_kwargs(**over):
    kw = dict(
        DEBUG=False,
        JWT_SECRET="x" * 32,
        AGENT_ENROLL_KEY="y" * 16,
        AEGIS_API_KEY="z" * 32,
        MASTER_KEY_B64="Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q=",
        REDIS_PASSWORD="w" * 16,
        ALLOW_OPEN_REGISTRATION=False,
    )
    kw.update(over)
    return kw


def test_prod_open_registration_refused():
    with pytest.raises(ValidationError):
        Settings(**_prod_kwargs(ALLOW_OPEN_REGISTRATION=True))


def test_prod_closed_registration_ok():
    s = Settings(**_prod_kwargs())
    assert s.ALLOW_OPEN_REGISTRATION is False


def test_lab_open_registration_ok():
    s = Settings(DEBUG=True, ALLOW_OPEN_REGISTRATION=True)
    assert s.ALLOW_OPEN_REGISTRATION is True


def test_enterprise_requires_closed_registration():
    with pytest.raises(ValidationError):
        Settings(DEBUG=True, ENTERPRISE_STRICT=True,
                 ALLOW_OPEN_REGISTRATION=True, MTLS_MODE="required")


def test_enterprise_requires_mtls():
    with pytest.raises(ValidationError):
        Settings(DEBUG=True, ENTERPRISE_STRICT=True,
                 ALLOW_OPEN_REGISTRATION=False, MTLS_MODE="off")
    s = Settings(DEBUG=True, ENTERPRISE_STRICT=True,
                 ALLOW_OPEN_REGISTRATION=False, MTLS_MODE="required")
    assert s.MTLS_MODE == "required"
