import hashlib
import os
from typing import Tuple

def hash_password(password: str, salt_hex: str = None) -> Tuple[str, str]:
    """
    Hashes the password with PBKDF2 HMAC SHA-256 and returns (hash_hex, salt_hex).
    If salt_hex is not provided, a random 16-byte salt is generated.
    """
    if salt_hex is None:
        salt_bytes = os.urandom(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)
        
    # Secure PBKDF2 with 100,000 iterations
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        100000
    )
    return hash_bytes.hex(), salt_hex

def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """
    Verifies that a password matches the stored hash and salt.
    """
    hash_hex, _ = hash_password(password, salt_hex)
    return hash_hex == stored_hash_hex
