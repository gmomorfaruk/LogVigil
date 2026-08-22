"""
key_locker.py — Triple-Lock File Protection Engine (Lock 3)

Lock 3 adds RSA-4096 + AES-256-GCM hybrid encryption on top of:
  Lock 1: Login password (PBKDF2-HMAC-SHA256)
  Lock 2: Vault PIN / Master Key (AES-256-GCM)

Security model:
  - A random AES-256 session key encrypts each file (fast, any size)
  - That session key is encrypted with RSA-4096 public key (small, asymmetric)
  - The RSA private key is stored encrypted with AES-256-GCM,
    protected by a PBKDF2-derived key from the user's Lock 3 passphrase
  - The passphrase is NEVER stored — only the encrypted private key is

Even if an attacker gets the entire database + vault access, they
cannot decrypt Lock 3 files without the Lock 3 passphrase.
"""

import os
import secrets
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RSA_KEY_SIZE       = 4096           # RSA key bits
AES_KEY_LEN        = 32             # AES-256 = 32 bytes
NONCE_LEN          = 12             # GCM nonce
PBKDF2_ITERATIONS  = 200_000        # Stronger than auth (passphrase is the last line of defence)
LOCK3_EXTENSION    = ".lv3"         # Extension for Lock 3 encrypted files


# ---------------------------------------------------------------------------
# Key Pair Generation
# ---------------------------------------------------------------------------

def generate_keypair(passphrase: str) -> tuple[str, str, str]:
    """
    Generate an RSA-4096 key pair.
    The private key is encrypted with AES-256-GCM using a key derived from
    the user's passphrase (PBKDF2-HMAC-SHA256, 200,000 iterations).

    Returns:
        (public_key_pem, encrypted_private_key_hex, salt_hex)

    The passphrase is never stored. Only the encrypted private key is stored.
    """
    # Generate RSA-4096 key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()

    # Serialize public key (plain — public key is not secret)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Serialize private key (unencrypted first, then we encrypt ourselves)
    private_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Derive AES key from passphrase
    salt = os.urandom(16)
    aes_key = _derive_aes_key(passphrase, salt)

    # Encrypt private key with AES-256-GCM
    nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(aes_key)
    enc_private = aesgcm.encrypt(nonce, private_pem_bytes, None)

    # Store as: nonce (12 bytes) + ciphertext, all hex-encoded
    encrypted_private_hex = (nonce + enc_private).hex()
    salt_hex = salt.hex()

    # Wipe sensitive material
    _wipe(aes_key)

    return public_pem, encrypted_private_hex, salt_hex


# ---------------------------------------------------------------------------
# File Encryption (Lock 3 Enable)
# ---------------------------------------------------------------------------

def lock_file(file_path: str, public_key_pem: str) -> tuple[str, str]:
    """
    Encrypt a file using hybrid RSA-4096 + AES-256-GCM encryption.

    Flow:
      1. Read file bytes
      2. Compute SHA-256 of plaintext (for future integrity verification)
      3. Generate a random 32-byte AES session key
      4. Encrypt file bytes with AES-256-GCM (session key)
      5. Encrypt session key with RSA-4096 public key
      6. Write .lv3 file: [rsa_len(4 bytes)] + [rsa_encrypted_key] + [nonce(12)] + [ciphertext]
      7. Return (lv3_path, plaintext_sha256_hex)

    The original file is NOT deleted — the caller can decide.
    """
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Hash plaintext for integrity baseline
    plaintext_hash = hashlib.sha256(plaintext).hexdigest()

    # Generate one-time AES session key
    aes_key = secrets.token_bytes(AES_KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    # Encrypt file content
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Encrypt AES session key with RSA public key
    pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    rsa_encrypted_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Wipe AES key from memory
    _wipe(aes_key)

    # Pack: [4-byte RSA blob length][RSA blob][12-byte nonce][ciphertext]
    rsa_len = len(rsa_encrypted_key).to_bytes(4, "big")
    lv3_payload = rsa_len + rsa_encrypted_key + nonce + ciphertext

    lv3_path = file_path + LOCK3_EXTENSION
    with open(lv3_path, "wb") as f:
        f.write(lv3_payload)

    return lv3_path, plaintext_hash


# ---------------------------------------------------------------------------
# File Decryption (Unlock / Verify)
# ---------------------------------------------------------------------------

def unlock_file_bytes(lv3_path: str, encrypted_private_hex: str,
                      salt_hex: str, passphrase: str) -> bytes:
    """
    Decrypt a .lv3 file and return the plaintext bytes.
    Raises ValueError on wrong passphrase or tampered file.

    This keeps decrypted content in memory only — never writes to disk.
    """
    # Reconstruct private key
    private_key = _load_private_key(encrypted_private_hex, salt_hex, passphrase)

    with open(lv3_path, "rb") as f:
        payload = f.read()

    # Parse: [4-byte RSA len][RSA blob][nonce][ciphertext]
    rsa_len = int.from_bytes(payload[:4], "big")
    rsa_blob = payload[4 : 4 + rsa_len]
    nonce = payload[4 + rsa_len : 4 + rsa_len + NONCE_LEN]
    ciphertext = payload[4 + rsa_len + NONCE_LEN :]

    # Decrypt session key with RSA private key
    try:
        aes_key = private_key.decrypt(
            rsa_blob,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("Decryption failed: wrong passphrase or corrupted key")

    # Decrypt file content
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("File integrity check failed: file has been tampered with")
    finally:
        _wipe(aes_key)

    return plaintext


def verify_file_integrity(lv3_path: str, baseline_sha256: str,
                           encrypted_private_hex: str,
                           salt_hex: str, passphrase: str) -> dict:
    """
    Decrypt a .lv3 file, hash the plaintext, compare to baseline.

    Returns:
        {"status": "UNMODIFIED" | "TAMPERED" | "ERROR", "message": str}
    """
    try:
        plaintext = unlock_file_bytes(lv3_path, encrypted_private_hex, salt_hex, passphrase)
    except FileNotFoundError:
        return {"status": "DELETED", "message": "Encrypted file not found on disk"}
    except ValueError as e:
        return {"status": "ERROR", "message": str(e)}

    current_hash = hashlib.sha256(plaintext).hexdigest()

    if current_hash == baseline_sha256:
        return {"status": "UNMODIFIED",
                "message": "File content matches baseline — no tampering detected"}
    else:
        return {"status": "TAMPERED",
                "message": f"Hash mismatch! Baseline: {baseline_sha256[:16]}... Current: {current_hash[:16]}..."}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _load_private_key(encrypted_private_hex: str, salt_hex: str, passphrase: str):
    """Decrypt and load the RSA private key from the stored encrypted form."""
    salt = bytes.fromhex(salt_hex)
    aes_key = _derive_aes_key(passphrase, salt)

    raw = bytes.fromhex(encrypted_private_hex)
    nonce = raw[:NONCE_LEN]
    ciphertext = raw[NONCE_LEN:]

    aesgcm = AESGCM(aes_key)
    try:
        private_pem_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong passphrase — cannot decrypt private key")
    finally:
        _wipe(aes_key)

    return serialization.load_pem_private_key(private_pem_bytes, password=None)


def _wipe(key_bytes) -> None:
    """Best-effort in-memory wipe of key material."""
    if isinstance(key_bytes, (bytes, bytearray)):
        try:
            mv = memoryview(bytearray(key_bytes))
            for i in range(len(mv)):
                mv[i] = 0
        except Exception:
            pass
