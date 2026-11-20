"""
Password security module.
Uses Argon2id for password hashing — one-way, irreversible.
Passwords are NEVER encrypted with AES; they are hashed.
"""
from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)

# Configure Argon2id with secure defaults
_hasher = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=4,      # Parallel threads
    hash_len=32,        # Hash output length
    salt_len=16,        # Salt length
    type=Type.ID,       # Argon2id
)


def hash_password(password):
    """
    Hash a password using Argon2id.
    Returns the full hash string including parameters and salt.
    """
    return _hasher.hash(password)


def verify_password(password_hash, password):
    """
    Verify a password against its Argon2id hash.
    Returns True if the password matches, False otherwise.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash):
    """
    Check if the hash needs to be re-computed with updated parameters.
    Useful for gradual migration to stronger settings.
    """
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return True
