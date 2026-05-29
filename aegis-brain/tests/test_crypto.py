import base64
import os
import pytest
from app.core.crypto import generate_dek, encrypt_dek_with_kek, decrypt_dek_with_kek, encrypt_for_user, decrypt_for_user
from app.core.config import settings

def test_dek_generation():
    dek = generate_dek()
    assert len(dek) == 32

def test_encryption_decryption_roundtrip(monkeypatch):
    # Mock master key for testing
    test_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    monkeypatch.setattr(settings, "MASTER_KEY_B64", test_key)

    plaintext = "super secret note data"
    
    dek = generate_dek()
    encrypted_dek = encrypt_dek_with_kek(dek)
    
    # Verify DEK can be decrypted
    decrypted_dek = decrypt_dek_with_kek(encrypted_dek)
    assert dek == decrypted_dek

    # Verify user data encryption
    encrypted_data = encrypt_for_user(encrypted_dek, plaintext)
    decrypted_data = decrypt_for_user(encrypted_dek, encrypted_data)
    
    assert decrypted_data == plaintext
