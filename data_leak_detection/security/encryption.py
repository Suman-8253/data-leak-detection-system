"""
AES-256-GCM encryption module.
Encrypts sensitive record payloads before database storage.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_encryption_key = None


def init_encryption(key_b64=None):
    """
    Initialize the encryption key from a base64-encoded string.
    Key must be exactly 32 bytes (256 bits) when decoded.
    """
    global _encryption_key
    if key_b64 is None:
        key_b64 = os.environ.get('ENCRYPTION_KEY', '')

    if not key_b64:
        print("[ENCRYPTION] WARNING: No encryption key configured. "
              "Encryption operations will fail.")
        _encryption_key = None
        return False

    try:
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) != 32:
            raise ValueError(
                f"Key must be exactly 32 bytes, got {len(key_bytes)}"
            )
        _encryption_key = key_bytes
        return True
    except Exception as e:
        print(f"[ENCRYPTION] ERROR: Invalid encryption key: {e}")
        _encryption_key = None
        return False


def get_key():
    """Get the current encryption key. Raises if not initialized."""
    if _encryption_key is None:
        raise RuntimeError("Encryption key not initialized. "
                           "Call init_encryption() first.")
    return _encryption_key


def encrypt(plaintext, associated_data=None):
    """
    Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: String to encrypt.
        associated_data: Optional additional authenticated data (bytes).

    Returns:
        (ciphertext_bytes, nonce_bytes) — ready for database storage.
    """
    key = get_key()
    aesgcm = AESGCM(key)

    # Generate a unique 12-byte nonce for each encryption
    nonce = os.urandom(12)

    plaintext_bytes = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
    aad = associated_data if associated_data else None

    # AESGCM.encrypt appends the authentication tag to the ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return ciphertext, nonce


def decrypt(ciphertext, nonce, associated_data=None):
    """
    Decrypt ciphertext using AES-256-GCM.

    Args:
        ciphertext: Encrypted bytes (with appended auth tag).
        nonce: The 12-byte nonce used during encryption.
        associated_data: Optional additional authenticated data (bytes).

    Returns:
        Decrypted string.

    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext was tampered.
        RuntimeError: If key is not initialized.
    """
    key = get_key()
    aesgcm = AESGCM(key)

    aad = associated_data if associated_data else None

    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext_bytes.decode('utf-8')


def decrypt_with_key(ciphertext, nonce, key_bytes, associated_data=None):
    """
    Decrypt with a specific key (for key-rotation or testing).
    Raises InvalidTag if the key or data is wrong.
    """
    aesgcm = AESGCM(key_bytes)
    aad = associated_data if associated_data else None
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext_bytes.decode('utf-8')


def generate_key():
    """Generate a new 256-bit key and return it as a base64-encoded string."""
    key = os.urandom(32)
    return base64.b64encode(key).decode('utf-8')


def is_key_configured():
    """Check if the encryption key has been initialized."""
    return _encryption_key is not None
