import pytest
import time
from app.core.security import hash_password, verify_password, needs_rehash, create_access_token, decode_access_token

def test_password_hashing():
    password = "MySecurePassword123!"
    hashed = hash_password(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False
    assert needs_rehash(hashed) is False

def test_jwt_creation_and_decoding():
    subject = "user123"
    role = "admin"
    
    token, jti, exp = create_access_token(subject, role)
    
    assert token is not None
    assert isinstance(jti, str)
    assert exp > time.time()
    
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == subject
    assert payload["role"] == role
    assert payload["jti"] == jti

def test_jwt_decoding_invalid():
    invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI.invalid.signature"
    assert decode_access_token(invalid_token) is None


def test_legacy_passlib_hash_migrates_to_pwdlib():
    """Migrazione graduale: hash passlib vecchi verificano e chiedono rehash;
    i nuovi hash pwdlib/argon2id non lo chiedono (P2.9)."""
    from passlib.context import CryptContext
    legacy = CryptContext(schemes=["argon2"], deprecated="auto").hash("pw123")
    assert verify_password("pw123", legacy) is True
    assert needs_rehash(legacy) is True
    new = hash_password("pw123")
    assert new.startswith("$argon2id$")
    assert verify_password("pw123", new) is True
    assert needs_rehash(new) is False
