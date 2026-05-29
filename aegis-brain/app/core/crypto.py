import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings

def generate_dek() -> bytes:
    """Generate a random 32-byte Data Encryption Key (DEK)."""
    return AESGCM.generate_key(bit_length=256)

def encrypt_dek_with_kek(dek: bytes) -> str:
    """Encrypt the DEK with the Master KEK (from env) and return as base64 string."""
    if not settings.MASTER_KEY_B64:
        raise ValueError("MASTER_KEY_B64 not configured")
    
    kek = base64.b64decode(settings.MASTER_KEY_B64)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, dek, None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_dek_with_kek(encrypted_dek_b64: str) -> bytes:
    """Decrypt the DEK using the Master KEK."""
    if not settings.MASTER_KEY_B64:
        raise ValueError("MASTER_KEY_B64 not configured")
    
    kek = base64.b64decode(settings.MASTER_KEY_B64)
    data = base64.b64decode(encrypted_dek_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_for_user(encrypted_dek_b64: str, plaintext: str) -> str:
    """Encrypt plaintext with the user's DEK (which is stored encrypted with KEK)."""
    dek = decrypt_dek_with_kek(encrypted_dek_b64)
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_for_user(encrypted_dek_b64: str, ciphertext_b64: str) -> str:
    """Decrypt ciphertext with the user's DEK."""
    dek = decrypt_dek_with_kek(encrypted_dek_b64)
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
