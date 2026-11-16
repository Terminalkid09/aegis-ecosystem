"""AEGIS-SEC-008: AEGIS_PROFILE=prod non deve partire con mTLS off."""
import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _settings(**overrides):
    values = {
        "_env_file": None,
        "DEBUG": True,
        "AEGIS_PROFILE": "prod",
        "MTLS_MODE": "required",
        "ENTERPRISE_STRICT": True,
        "ALLOW_OPEN_REGISTRATION": False,
        "RATE_LIMIT_STORAGE_URI": "redis://localhost:6379/1",
    }
    values.update(overrides)
    return Settings(**values)


def test_prod_profile_rejects_mtls_off():
    with pytest.raises(ValidationError, match="MTLS_MODE=required"):
        _settings(MTLS_MODE="off")


def test_prod_profile_rejects_non_strict():
    with pytest.raises(ValidationError, match="ENTERPRISE_STRICT=true"):
        _settings(ENTERPRISE_STRICT=False)


def test_prod_profile_accepts_required_and_strict():
    settings = _settings()
    assert settings.MTLS_MODE == "required"
    assert settings.ENTERPRISE_STRICT is True
