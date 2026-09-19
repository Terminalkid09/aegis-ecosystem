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


# ── Validazione dei secret: gira solo fuori dal lab ──────────────────────────
# Questi test esistono perche' il compose scriveva DEBUG a mano: il profilo di
# produzione non veniva mai applicato e la validazione dei secret non girava
# mai, in nessun deploy. Verificarla qui la rende indipendente dall'ambiente.

@pytest.mark.parametrize("field,value", [
    ("JWT_SECRET", "corto"),
    ("AGENT_ENROLL_KEY", "x" * 8),
    ("AEGIS_API_KEY", "y" * 20),
])
def test_prod_rejects_short_secrets(field, value):
    with pytest.raises(ValidationError):
        Settings(**_prod_kwargs(**{field: value}))


@pytest.mark.parametrize("field", ["JWT_SECRET", "AGENT_ENROLL_KEY",
                                   "AEGIS_API_KEY", "REDIS_PASSWORD"])
def test_prod_rejects_placeholder_markers(field):
    """Un valore lungo ma esemplificativo e' peggio di uno corto: sembra ok."""
    with pytest.raises(ValidationError):
        Settings(**_prod_kwargs(**{field: "for_v4.0.0-change-me-aaaaaaaaaaaaaa"}))


def test_prod_rejects_master_key_of_wrong_size():
    import base64
    bad = base64.b64encode(b"tooshort").decode()
    with pytest.raises(ValidationError):
        Settings(**_prod_kwargs(MASTER_KEY_B64=bad))


def test_prod_accepts_a_coherent_configuration():
    s = Settings(**_prod_kwargs())
    assert s.DEBUG is False


def test_cookie_secure_is_independent_from_debug():
    """Il flag Secure non deve dipendere dalla verbosita' dei log.

    Prima era `secure=not DEBUG`: accendere il debug per una diagnosi toglieva
    il flag a un cookie di sessione. Ora sono due cose separate.
    """
    assert Settings(**_prod_kwargs(DEBUG=True, COOKIE_SECURE=True)).COOKIE_SECURE is True
    assert Settings(**_prod_kwargs(COOKIE_SECURE=False)).COOKIE_SECURE is False
    # Default: sicuro.
    assert Settings(**_prod_kwargs()).COOKIE_SECURE is True
