import os
import secrets
import hashlib
import sqlite3
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, Field
from typing import List, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db import get_db
from logger import log_event
from security_service import (
    hash_master_key,
    verify_master_key,
    check_vault_lockout,
    record_vault_failure,
    reset_vault_security,
    get_current_unlock_stage,
    create_vault_session,
    validate_vault_session,
    touch_vault_session,
    invalidate_vault_session,
    wipe_vault_key,
    LOCKOUT_SCHEDULE,
    DEFAULT_LOCKOUT,
    VAULT_SESSION_TTL_SECONDS,
)

router = APIRouter(prefix="/api/vault", tags=["Vault"])

# In-memory derived key store (username -> key bytes).
# The actual session validity is now DB-backed via vault_sessions.
# This dict only holds the key material for active, validated sessions.
active_vault_sessions = {}  # username -> derived_key bytes

# Global vault lock state (still used for quick status checks)
vault_state = {"locked": True}


# ---------------------------------------------------------------------------
# PIN helpers
# ---------------------------------------------------------------------------

def hash_pin(pin: str, salt_hex: str = None):
    """Hash a PIN with PBKDF2-HMAC-SHA256. Returns (hash_hex, salt_hex)."""
    if salt_hex is None:
        salt_bytes = os.urandom(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    hash_bytes = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt_bytes, 100000)
    return hash_bytes.hex(), salt_hex


def verify_pin(pin: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """Verify a PIN against stored hash and salt."""
    hash_hex, _ = hash_pin(pin, salt_hex)
    return hash_hex == stored_hash_hex


def derive_key(pin: str, vault_salt_hex: str) -> bytes:
    """Derive AES-256 key from PIN using a per-user vault salt."""
    vault_salt = bytes.fromhex(vault_salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_salt,
        iterations=100000
    )
    return kdf.derive(pin.encode('utf-8'))


def derive_key_from_master_key(master_key: str, vault_salt_hex: str) -> bytes:
    """Derive AES-256 key from Master Key using a per-user vault salt."""
    vault_salt = bytes.fromhex(vault_salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_salt,
        iterations=100000
    )
    return kdf.derive(master_key.encode('utf-8'))


def encrypt_vault_key(vault_key: bytes, derivation_key: bytes) -> str:
    """Encrypt the raw vault key with a derivation key (PIN or Master Key derived) using AES-GCM."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(derivation_key)
    ciphertext = aesgcm.encrypt(nonce, vault_key, None)
    return (nonce + ciphertext).hex()


def decrypt_vault_key(encrypted_vault_key_hex: str, derivation_key: bytes) -> bytes:
    """Decrypt the raw vault key with a derivation key using AES-GCM."""
    raw_bytes = bytes.fromhex(encrypted_vault_key_hex)
    if len(raw_bytes) < 12:
        raise ValueError("Encrypted vault key payload corrupted (too short)")
    nonce = raw_bytes[:12]
    ciphertext = raw_bytes[12:]
    aesgcm = AESGCM(derivation_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _resolve_username(authorization: Optional[str]) -> Optional[str]:
    """Extract username from the auth sessions table (or in-memory fallback)."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM sessions WHERE token = ?", (token,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row["username"]
    except Exception:
        pass

    try:
        from auth.router import active_sessions
        return active_sessions.get(token)
    except Exception:
        return None


def _get_user_id(conn, username: str) -> Optional[int]:
    """Look up user_id for a given username."""
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class VaultToggleRequest(BaseModel):
    pin: Optional[str] = Field(None, min_length=4, max_length=8)
    master_key: Optional[str] = Field(None, min_length=4)


class VaultSetupPinRequest(BaseModel):
    pin: str = Field(..., min_length=4, max_length=8)
    master_key: Optional[str] = Field(None, min_length=4)


class VaultStatusResponse(BaseModel):
    locked: bool
    has_pin: bool = False
    has_master_key: bool = False
    unlock_stage: Optional[str] = None    # 'pin' | 'master_key' | 'cooldown'
    lockout_seconds: Optional[int] = None


class VaultFile(BaseModel):
    file_id: str
    file_name: str
    path: str
    encrypted_at: str
    size: int


class FileEncryptRequest(BaseModel):
    file_path: str = Field(..., min_length=1)


class FileEncryptResponse(BaseModel):
    file_id: str
    file_name: str
    encrypted_path: str
    size: int


class FileDecryptRequest(BaseModel):
    file_id: str = Field(..., min_length=1)


class FileDecryptResponse(BaseModel):
    file_name: str
    decrypted_path: str


class CredentialCreate(BaseModel):
    website: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)


class CredentialResponse(BaseModel):
    id: int
    website: str
    username: str
    password: str


# ---------------------------------------------------------------------------
# Session validation helper used by all protected endpoints
# ---------------------------------------------------------------------------

def _require_vault_session(authorization: Optional[str]) -> tuple:
    """
    Validates that:
      1. The user is authenticated (has a valid Bearer token)
      2. The vault is unlocked (vault_state)
      3. The DB-backed vault session is still valid (not expired by inactivity)

    On success: returns (username, user_id, conn)
    On failure: raises HTTPException and performs cleanup if session expired.
    """
    username = _resolve_username(authorization)
    if not username:
        raise HTTPException(status_code=401, detail="Authentication required")

    conn = get_db()
    user_id = _get_user_id(conn, username)
    if not user_id:
        conn.close()
        raise HTTPException(status_code=401, detail="User not found")

    if vault_state["locked"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Vault is locked. Access denied.")

    # Backend is the security authority — validate DB session
    if not validate_vault_session(conn, user_id):
        # Session expired — enforce auto-lock
        vault_state["locked"] = True
        wipe_vault_key(active_vault_sessions, username)
        log_event("WARNING", f"Vault session expired due to inactivity for operator '{username}'. Auto-locked.", operator=username)
        conn.close()
        raise HTTPException(
            status_code=401,
            detail="Vault session expired due to inactivity",
            headers={"X-Vault-Reason": "inactivity"}
        )

    # Session valid — refresh TTL on every authenticated vault activity
    touch_vault_session(conn, user_id)
    return username, user_id, conn


def _get_derived_key(authorization: Optional[str] = None) -> bytes:
    """Get the active derived key for the current user, or raise 500."""
    username = _resolve_username(authorization)
    if username and username in active_vault_sessions:
        return active_vault_sessions[username]

    if active_vault_sessions:
        return next(iter(active_vault_sessions.values()))

    raise HTTPException(status_code=500, detail="Vault session corrupted. Re-authenticate.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=VaultStatusResponse)
def get_vault_status(authorization: Optional[str] = Header(None)):
    username = _resolve_username(authorization)
    has_pin = False
    has_master_key = False
    unlock_stage = "pin"
    lockout_seconds = None

    if username:
        try:
            conn = get_db()
            cursor = conn.cursor()

            # Check if user has a PIN and whether master key is set
            cursor.execute(
                "SELECT vp.user_id, vp.master_key_hash FROM vault_pins vp JOIN users u ON vp.user_id = u.id WHERE u.username = ?",
                (username,)
            )
            pin_row = cursor.fetchone()
            has_pin = pin_row is not None
            has_master_key = bool(pin_row and pin_row["master_key_hash"])

            # Check lockout + stage
            user_id = _get_user_id(conn, username)
            if user_id:
                is_locked_out, secs = check_vault_lockout(conn, user_id)
                if is_locked_out:
                    lockout_seconds = secs
                    unlock_stage = "cooldown"
                else:
                    raw_stage = get_current_unlock_stage(conn, user_id)
                    # KEY FIX: If stage would be master_key but no master key is configured,
                    # auto-reset the counter and fall back to pin stage.
                    # This prevents the user getting permanently trapped.
                    if raw_stage == "master_key" and not has_master_key:
                        reset_vault_security(conn, user_id)
                        log_event("INFO", f"Vault security counter auto-reset: no master key configured for '{username}'")
                        unlock_stage = "pin"
                    else:
                        unlock_stage = raw_stage

            conn.close()
        except Exception:
            pass

    return {
        "locked": vault_state["locked"],
        "has_pin": has_pin,
        "has_master_key": has_master_key,
        "unlock_stage": unlock_stage,
        "lockout_seconds": lockout_seconds
    }


@router.post("/setup-pin")
def setup_vault_pin(req: VaultSetupPinRequest, authorization: Optional[str] = Header(None)):
    """First-time PIN + optional Master Key setup for a user."""
    username = _resolve_username(authorization)
    if not username:
        raise HTTPException(status_code=401, detail="Authentication required to set up vault PIN")

    conn = get_db()
    cursor = conn.cursor()

    user_id = _get_user_id(conn, username)
    if not user_id:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Check if PIN already exists
    cursor.execute("SELECT user_id FROM vault_pins WHERE user_id = ?", (user_id,))
    if cursor.fetchone():
        conn.close()
        log_event("WARNING", f"Vault PIN setup rejected: PIN already exists for operator '{username}'")
        raise HTTPException(status_code=400, detail="Vault PIN already configured. Use the existing PIN to unlock.")

    # Hash the PIN (PBKDF2 — for vault access)
    pin_hash_hex, pin_salt_hex = hash_pin(req.pin)
    vault_salt_hex = os.urandom(32).hex()

    # Generate core vault key
    vault_key = os.urandom(32)
    pin_key = derive_key(req.pin, vault_salt_hex)
    encrypted_key_by_pin = encrypt_vault_key(vault_key, pin_key)

    # Hash master key with Argon2id if provided, and encrypt core vault key with it
    master_key_hash = None
    encrypted_key_by_master = None
    if req.master_key:
        master_key_hash = hash_master_key(req.master_key)
        master_key_derived_key = derive_key_from_master_key(req.master_key, vault_salt_hex)
        encrypted_key_by_master = encrypt_vault_key(vault_key, master_key_derived_key)

    try:
        cursor.execute(
            "INSERT INTO vault_pins (user_id, pin_hash, pin_salt, vault_salt, master_key_hash, encrypted_key_by_pin, encrypted_key_by_master) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, pin_hash_hex, pin_salt_hex, vault_salt_hex, master_key_hash, encrypted_key_by_pin, encrypted_key_by_master)
        )
        conn.commit()
        has_master = "with Master Key" if master_key_hash else "without Master Key"
        log_event("INFO", f"Vault PIN configured {has_master} for operator: '{username}'", operator=username)
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to store vault PIN for '{username}': {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    msg = "Vault PIN configured successfully"
    if master_key_hash:
        msg += " with Master Key protection"
    return {"message": msg, "has_master_key": master_key_hash is not None}


@router.post("/toggle", response_model=VaultStatusResponse)
def toggle_vault(req: VaultToggleRequest, authorization: Optional[str] = Header(None)):
    """
    Unlock or lock the vault.

    Unlock flow (layered security):
      Stage 'pin':        Requires req.pin — verified with PBKDF2
      Stage 'master_key': Requires req.master_key — verified with Argon2id

    Lockout is progressive: 30min → 2h → 24h (no permanent lock)
    """
    username = _resolve_username(authorization)

    conn = get_db()
    cursor = conn.cursor()

    # ---- LOCK REQUEST ----
    if not vault_state["locked"]:
        # Currently unlocked — user wants to lock
        has_master_key_val = False
        if username:
            user_id = _get_user_id(conn, username)
            if user_id:
                invalidate_vault_session(conn, user_id)
                # CRITICAL: Reset failed_attempts on lock.
                # The user successfully authenticated to reach this state,
                # so all prior PIN failures are forgiven. This prevents
                # the master_key stage from persisting across lock/unlock cycles.
                reset_vault_security(conn, user_id)
                # Read has_master_key to return accurate state
                cursor.execute("SELECT master_key_hash FROM vault_pins WHERE user_id = ?", (user_id,))
                mk_row = cursor.fetchone()
                has_master_key_val = bool(mk_row and mk_row["master_key_hash"])
            wipe_vault_key(active_vault_sessions, username)
        else:
            active_vault_sessions.clear()

        vault_state["locked"] = True
        log_event("INFO", f"Vault locked by operator '{username or 'unknown'}'")
        conn.close()
        return {
            "locked": True,
            "has_pin": True,
            "has_master_key": has_master_key_val,
            "unlock_stage": "pin",
            "lockout_seconds": None
        }

    # ---- UNLOCK REQUEST ----
    # Fetch user's vault PIN record
    pin_row = None
    user_id = None
    if username:
        user_id = _get_user_id(conn, username)
        if user_id:
            cursor.execute(
                "SELECT pin_hash, pin_salt, vault_salt, master_key_hash, encrypted_key_by_pin, encrypted_key_by_master FROM vault_pins WHERE user_id = ?",
                (user_id,)
            )
            pin_row = cursor.fetchone()

    if not pin_row:
        conn.close()
        log_event("WARNING", f"Vault access attempt without configured PIN for '{username or 'unknown'}'")
        raise HTTPException(status_code=400, detail="No vault PIN configured. Please set up your vault PIN first.")

    # Check if currently locked out
    if user_id:
        is_locked_out, secs_remaining = check_vault_lockout(conn, user_id)
        if is_locked_out:
            conn.close()
            minutes = (secs_remaining + 59) // 60
            raise HTTPException(
                status_code=429,
                detail=f"Access temporarily restricted. Try again in {minutes} minute(s).",
                headers={"X-Lockout-Seconds": str(secs_remaining)}
            )

    # Determine which stage we're in
    current_stage = get_current_unlock_stage(conn, user_id) if user_id else "pin"

    vault_salt_hex = pin_row["vault_salt"]

    if current_stage == "pin":
        # ---- Stage 1: Verify PIN ----
        if not req.pin:
            conn.close()
            raise HTTPException(status_code=400, detail="Security PIN is required")

        if verify_pin(req.pin, pin_row["pin_salt"], pin_row["pin_hash"]):
            # SUCCESS — unlock
            pin_key = derive_key(req.pin, vault_salt_hex)
            
            # Retrieve or migrate vault_key
            encrypted_key_by_pin = pin_row["encrypted_key_by_pin"]
            if encrypted_key_by_pin:
                try:
                    vault_key = decrypt_vault_key(encrypted_key_by_pin, pin_key)
                except Exception as e:
                    log_event("ERROR", f"Failed to decrypt vault_key using PIN-key: {str(e)}")
                    conn.close()
                    raise HTTPException(status_code=500, detail="Failed to decrypt vault key")
            else:
                # BACKWARD COMPATIBILITY MIGRATION:
                vault_key = pin_key
                try:
                    encrypted_key_by_pin = encrypt_vault_key(vault_key, pin_key)
                    cursor.execute(
                        "UPDATE vault_pins SET encrypted_key_by_pin = ? WHERE user_id = ?",
                        (encrypted_key_by_pin, user_id)
                    )
                    conn.commit()
                    log_event("INFO", f"Migrated legacy vault to new vault_key schema for '{username}'")
                except Exception as e:
                    log_event("WARNING", f"Failed to save migrated vault key for '{username}': {str(e)}")

            active_vault_sessions[username] = vault_key
            vault_state["locked"] = False
            create_vault_session(conn, user_id)
            reset_vault_security(conn, user_id)
            log_event("INFO", f"Vault unlocked successfully for operator '{username}'", operator=username)
            conn.close()
            return {"locked": False, "has_pin": True, "unlock_stage": "pin", "lockout_seconds": None}
        else:
            # WRONG PIN — escalate to master_key stage
            new_count, lockout_secs = record_vault_failure(conn, user_id)
            log_event("WARNING", f"Vault PIN failed for operator '{username}' (attempt {new_count})")
            conn.close()

            if lockout_secs > 0:
                minutes = (lockout_secs + 59) // 60
                raise HTTPException(
                    status_code=429,
                    detail=f"Access temporarily restricted. Try again in {minutes} minute(s).",
                    headers={"X-Lockout-Seconds": str(lockout_secs)}
                )
            # First failure: no lockout, just require master key next
            raise HTTPException(
                status_code=401,
                detail="Additional verification required",
                headers={"X-Vault-Stage": "master_key"}
            )

    else:
        # ---- Stage 2+: Verify Master Key (Argon2id) ----
        if not req.master_key:
            conn.close()
            raise HTTPException(
                status_code=401,
                detail="Additional verification required",
                headers={"X-Vault-Stage": "master_key"}
            )

        master_key_hash = pin_row["master_key_hash"]
        if not master_key_hash:
            # No master key configured — cannot ask for it.
            # Auto-reset the security counter so user can try PIN again.
            reset_vault_security(conn, user_id)
            conn.close()
            log_event(
                "WARNING",
                f"Vault stage reset: master key required but not configured for operator '{username}'. Counter cleared."
            )
            # Return 200 with stage=pin so frontend knows to show PIN form again
            return {
                "locked": True,
                "has_pin": True,
                "has_master_key": False,
                "unlock_stage": "pin",
                "lockout_seconds": None
            }

        if verify_master_key(req.master_key, master_key_hash):
            # MASTER KEY CORRECT — unlock and reset all counters
            master_key_derived_key = derive_key_from_master_key(req.master_key, vault_salt_hex)
            
            encrypted_key_by_master = pin_row["encrypted_key_by_master"]
            if encrypted_key_by_master:
                try:
                    vault_key = decrypt_vault_key(encrypted_key_by_master, master_key_derived_key)
                except Exception as e:
                    log_event("ERROR", f"Failed to decrypt vault_key using Master Key: {str(e)}")
                    conn.close()
                    raise HTTPException(status_code=500, detail="Failed to decrypt vault key using Master Key")
            else:
                # Backward compatibility fallback
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2
                _kdf = _PBKDF2(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=bytes.fromhex(vault_salt_hex),
                    iterations=100000
                )
                vault_key = _kdf.derive(req.master_key.encode('utf-8'))
                log_event("WARNING", f"Legacy unlock via master key: vault key decryption not possible for '{username}'. Decryption errors may occur.")

            active_vault_sessions[username] = vault_key
            vault_state["locked"] = False
            create_vault_session(conn, user_id)
            reset_vault_security(conn, user_id)
            log_event("INFO", f"Vault unlocked via master key for operator '{username}'", operator=username)
            conn.close()
            return {"locked": False, "has_pin": True, "unlock_stage": "master_key", "lockout_seconds": None}
        else:
            # WRONG MASTER KEY — apply progressive lockout
            new_count, lockout_secs = record_vault_failure(conn, user_id)
            log_event(
                "WARNING" if new_count <= 3 else "CRITICAL",
                f"Vault master key failed for operator '{username}' (attempt {new_count})"
            )
            conn.close()
            minutes = (lockout_secs + 59) // 60
            raise HTTPException(
                status_code=429,
                detail=f"Access temporarily restricted. Try again in {minutes} minute(s).",
                headers={"X-Lockout-Seconds": str(lockout_secs)}
            )


@router.post("/inactivity-ping")
def inactivity_ping(authorization: Optional[str] = Header(None)):
    """
    Lightweight endpoint for frontend to call when vault is open but idle.
    Keeps the DB-backed vault session alive if the user is present.
    Backend validates and refreshes the session.
    """
    try:
        username, user_id, conn = _require_vault_session(authorization)
        conn.close()
        return {"status": "alive"}
    except HTTPException as e:
        raise


class MasterKeySetupRequest(BaseModel):
    current_pin: str = Field(..., min_length=4, max_length=8, description="Current vault PIN to verify identity")
    master_key: str = Field(..., min_length=4, description="New master key to set")


@router.post("/setup-master-key")
def setup_master_key(req: MasterKeySetupRequest, authorization: Optional[str] = Header(None)):
    """
    Configure or update the vault master key.
    Vault must be unlocked (active session) AND the current PIN re-entered to verify identity.
    Master key is hashed with Argon2id before storage.
    """
    # Vault must be unlocked to access this — proves operator is authenticated
    username, user_id, conn = _require_vault_session(authorization)

    cursor = conn.cursor()
    cursor.execute(
        "SELECT pin_hash, pin_salt, vault_salt FROM vault_pins WHERE user_id = ?",
        (user_id,)
    )
    pin_row = cursor.fetchone()

    if not pin_row:
        conn.close()
        raise HTTPException(status_code=404, detail="No vault PIN configured")

    # Re-verify current PIN before allowing master key change
    if not verify_pin(req.current_pin, pin_row["pin_salt"], pin_row["pin_hash"]):
        conn.close()
        log_event("WARNING", f"Master key setup failed: incorrect PIN for operator '{username}'", operator=username)
        raise HTTPException(status_code=401, detail="Current PIN is incorrect")

    # Get active vault key and encrypt it using the new master key
    try:
        vault_key = _get_derived_key(authorization)
        master_key_derived_key = derive_key_from_master_key(req.master_key, pin_row["vault_salt"])
        encrypted_key_by_master = encrypt_vault_key(vault_key, master_key_derived_key)
    except Exception as e:
        conn.close()
        log_event("ERROR", f"Failed to encrypt vault key with new master key: {str(e)}")
        raise HTTPException(status_code=500, detail="Key derivation error")

    # Hash the new master key with Argon2id
    new_master_key_hash = hash_master_key(req.master_key)

    try:
        cursor.execute(
            "UPDATE vault_pins SET master_key_hash = ?, encrypted_key_by_master = ? WHERE user_id = ?",
            (new_master_key_hash, encrypted_key_by_master, user_id)
        )
        conn.commit()
        log_event("INFO", f"Vault master key configured successfully for operator '{username}'", operator=username)
    except Exception as e:
        conn.close()
        log_event("ERROR", f"Failed to store master key for '{username}': {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    return {"message": "Master key configured successfully", "has_master_key": True}



@router.get("/files", response_model=List[VaultFile])
def get_vault_files(authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)

    cursor = conn.cursor()
    cursor.execute("SELECT file_id, file_name, original_path, encrypted_at, size FROM encrypted_files")
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "file_id": row["file_id"],
            "file_name": row["file_name"],
            "path": row["original_path"],
            "encrypted_at": row["encrypted_at"],
            "size": row["size"]
        } for row in rows
    ]


@router.post("/encrypt", response_model=FileEncryptResponse)
def encrypt_file(req: FileEncryptRequest, authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)
    derived_key = _get_derived_key(authorization)

    file_name = req.file_path.split("/")[-1]
    is_mock = "/home/user" in req.file_path

    if not is_mock:
        if not os.path.exists(req.file_path):
            raise HTTPException(status_code=404, detail="File path does not exist on this device")
        if os.path.isdir(req.file_path):
            raise HTTPException(status_code=400, detail="The specified path is a directory. Only individual files can be encrypted.")

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM encrypted_files")
    count_row = cursor.fetchone()
    count = count_row["count"] if count_row else 0
    file_id = f"file_{count + 1:03d}"

    encrypted_path = f"{req.file_path}.enc"
    encrypted_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if is_mock:
        dummy_content = b"SecureVault Mock File Contents AES-256-GCM Signature"
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, dummy_content, None)

        sandbox_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        os.makedirs(sandbox_dir, exist_ok=True)
        sandbox_file = os.path.join(sandbox_dir, f"mock_vault_{file_id}.enc")

        with open(sandbox_file, "wb") as f:
            f.write(nonce + ciphertext)

        size = len(dummy_content)
    else:
        try:
            size = os.path.getsize(req.file_path)
            chunk_size = 32 * 1024 * 1024  # 32MB streaming chunks
            aesgcm = AESGCM(derived_key)
            seq = 0

            with open(req.file_path, "rb") as fin, open(encrypted_path, "wb") as fout:
                fout.write(b"SVSTREAM")
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    nonce = seq.to_bytes(12, 'big')
                    ciphertext = aesgcm.encrypt(nonce, chunk, None)
                    fout.write(len(ciphertext).to_bytes(4, 'big'))
                    fout.write(ciphertext)
                    seq += 1

            os.remove(req.file_path)
        except Exception as e:
            if os.path.exists(encrypted_path):
                try:
                    os.remove(encrypted_path)
                except Exception:
                    pass
            conn.close()
            log_event("ERROR", f"File encryption I/O error on '{req.file_path}': {str(e)}")
            raise HTTPException(status_code=500, detail=f"File system write error: {str(e)}")

    try:
        cursor.execute(
            "INSERT INTO encrypted_files (file_id, file_name, original_path, encrypted_path, encrypted_at, size) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, file_name, req.file_path, encrypted_path, encrypted_at, size)
        )
        conn.commit()
        log_event("INFO", f"File encrypted successfully: '{file_name}' (ID: {file_id})")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to save encrypted file metadata: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    return {
        "file_id": file_id,
        "file_name": file_name,
        "encrypted_path": encrypted_path,
        "size": size
    }


@router.post("/decrypt", response_model=FileDecryptResponse)
def decrypt_file(req: FileDecryptRequest, authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)
    derived_key = _get_derived_key(authorization)

    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_name, original_path, encrypted_path FROM encrypted_files WHERE file_id = ?",
        (req.file_id,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        log_event("WARNING", f"File decryption failed: File ID '{req.file_id}' not found in database")
        raise HTTPException(status_code=404, detail="File not found in vault")

    file_name = row["file_name"]
    original_path = row["original_path"]
    encrypted_path = row["encrypted_path"]

    is_mock = "/home/user" in original_path or not os.path.exists(encrypted_path)

    if is_mock:
        sandbox_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        sandbox_file = os.path.join(sandbox_dir, f"mock_vault_{req.file_id}.enc")

        if os.path.exists(sandbox_file):
            try:
                os.remove(sandbox_file)
            except OSError:
                pass
    else:
        try:
            aesgcm = AESGCM(derived_key)
            with open(encrypted_path, "rb") as fin:
                header = fin.read(8)
                is_stream = (header == b"SVSTREAM")
                if not is_stream:
                    fin.seek(0)

            if is_stream:
                seq = 0
                with open(encrypted_path, "rb") as fin, open(original_path, "wb") as fout:
                    fin.seek(8)
                    while True:
                        len_bytes = fin.read(4)
                        if not len_bytes:
                            break
                        ct_len = int.from_bytes(len_bytes, 'big')
                        ciphertext = fin.read(ct_len)
                        nonce = seq.to_bytes(12, 'big')
                        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                        fout.write(plaintext)
                        seq += 1
            else:
                with open(encrypted_path, "rb") as f:
                    raw_bytes = f.read()

                if len(raw_bytes) < 12:
                    raise ValueError("Encrypted file payload corrupted (too short)")

                nonce = raw_bytes[:12]
                ciphertext = raw_bytes[12:]
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                with open(original_path, "wb") as f:
                    f.write(plaintext)

            os.remove(encrypted_path)
        except Exception as e:
            if os.path.exists(original_path):
                try:
                    os.remove(original_path)
                except Exception:
                    pass
            conn.close()
            log_event("ERROR", f"File decryption failure on '{encrypted_path}': {str(e)}")
            raise HTTPException(status_code=500, detail=f"Decryption I/O error: {str(e)}")

    try:
        cursor.execute("DELETE FROM encrypted_files WHERE file_id = ?", (req.file_id,))
        conn.commit()
        log_event("INFO", f"File decrypted successfully: '{file_name}' (ID: {req.file_id})")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to delete encrypted file metadata: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    return {"file_name": file_name, "decrypted_path": original_path}


@router.get("/passwords", response_model=List[CredentialResponse])
def get_vault_passwords(authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)
    derived_key = _get_derived_key(authorization)

    cursor = conn.cursor()
    cursor.execute("SELECT id, website, username, encrypted_password FROM password_vault")
    rows = cursor.fetchall()
    conn.close()

    aesgcm = AESGCM(derived_key)
    credentials = []
    for row in rows:
        try:
            raw_bytes = bytes.fromhex(row["encrypted_password"])
            if len(raw_bytes) < 12:
                raise ValueError("Payload too short")
            nonce = raw_bytes[:12]
            ciphertext = raw_bytes[12:]
            decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            credentials.append({
                "id": row["id"],
                "website": row["website"],
                "username": row["username"],
                "password": decrypted
            })
        except Exception:
            credentials.append({
                "id": row["id"],
                "website": row["website"],
                "username": row["username"],
                "password": "[DECRYPTION_ERROR]"
            })

    return credentials


@router.post("/passwords", response_model=CredentialResponse, status_code=201)
def create_vault_password(req: CredentialCreate, authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)
    derived_key = _get_derived_key(authorization)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, req.password.encode('utf-8'), None)
    encrypted_pwd_hex = (nonce + ciphertext).hex()

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO password_vault (website, username, encrypted_password) VALUES (?, ?, ?)",
            (req.website, req.username, encrypted_pwd_hex)
        )
        conn.commit()
        new_id = cursor.lastrowid
        log_event("INFO", f"Credential stored for: '{req.website}' (User: '{req.username}')")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to store credential: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    return {
        "id": new_id,
        "website": req.website,
        "username": req.username,
        "password": req.password
    }


@router.delete("/passwords/{id}")
def delete_vault_password(id: int, authorization: Optional[str] = Header(None)):
    username, user_id, conn = _require_vault_session(authorization)

    cursor = conn.cursor()
    cursor.execute("SELECT website, username FROM password_vault WHERE id = ?", (id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        log_event("WARNING", f"Password deletion failed: Credential ID '{id}' not found")
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        cursor.execute("DELETE FROM password_vault WHERE id = ?", (id,))
        conn.commit()
        log_event("INFO", f"Credential deleted: '{row['website']}' (User: '{row['username']}')")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to delete credential: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")

    conn.close()
    return {"message": "Credential deleted successfully"}
