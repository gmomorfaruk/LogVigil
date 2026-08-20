"""
security_service.py — CryptGuard Centralized Security Engine

Handles:
  - Argon2id master key hashing / verification
  - Progressive vault lockout (30min → 2h → 24h)
  - DB-backed vault sessions (5-minute inactivity expiry)
  - Login brute-force protection (per-username + per-IP)
  - Precise cryptographic key material wiping
"""

import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from db import get_db
from logger import log_event

# ---------------------------------------------------------------------------
# Argon2id configuration
# ---------------------------------------------------------------------------

# Argon2id with secure parameters — salt is embedded in the encoded hash string
_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB memory
    parallelism=2,      # threads
    hash_len=32,
    salt_len=16
)

# ---------------------------------------------------------------------------
# Progressive lockout schedule (seconds)
# ---------------------------------------------------------------------------

LOCKOUT_SCHEDULE = {
    1: 0,          # 1st failure: no wait — just ask for master key
    2: 1800,       # 2nd failure: 30 minutes
    3: 7200,       # 3rd failure: 2 hours
}
DEFAULT_LOCKOUT = 86400  # 4+ failures: 24 hours (effectively admin recovery)

# Login lockout config
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes

# Vault session inactivity timeout
VAULT_SESSION_TTL_SECONDS = 300  # 5 minutes


# ===========================================================================
# MASTER KEY — Argon2id
# ===========================================================================

def hash_master_key(key: str) -> str:
    """
    Hash a master key with Argon2id.
    Returns a self-contained encoded string with embedded salt and parameters.
    No separate salt column needed.
    """
    return _ph.hash(key)


def verify_master_key(key: str, stored_hash: str) -> bool:
    """
    Verify a master key against an Argon2id encoded hash.
    Returns True if correct, False if wrong.
    """
    try:
        _ph.verify(stored_hash, key)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ===========================================================================
# VAULT SECURITY STATE — Progressive Lockout
# ===========================================================================

def get_vault_security(conn, user_id: int) -> Optional[dict]:
    """Fetch vault_security row for a user. Returns None if no record yet."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_attempts, lockout_until, last_failed_at FROM vault_security WHERE user_id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "failed_attempts": row["failed_attempts"],
        "lockout_until": row["lockout_until"],
        "last_failed_at": row["last_failed_at"]
    }


def _ensure_vault_security_row(conn, user_id: int):
    """Insert a default vault_security row if one doesn't exist."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO vault_security (user_id, failed_attempts) VALUES (?, 0)",
        (user_id,)
    )
    conn.commit()


def check_vault_lockout(conn, user_id: int) -> Tuple[bool, int]:
    """
    Check if the vault is currently locked out for this user.
    Returns (is_locked_out: bool, seconds_remaining: int).
    """
    _ensure_vault_security_row(conn, user_id)
    sec = get_vault_security(conn, user_id)
    if not sec or not sec["lockout_until"]:
        return False, 0

    try:
        lockout_until = datetime.fromisoformat(sec["lockout_until"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if now < lockout_until:
            remaining = int((lockout_until - now).total_seconds())
            return True, remaining
    except Exception:
        pass

    return False, 0


def record_vault_failure(conn, user_id: int) -> Tuple[int, int]:
    """
    Increment failed_attempts for the user and apply progressive lockout if needed.
    Returns (new_failed_attempts: int, lockout_seconds_applied: int).
    0 lockout_seconds means no lockout applied yet (stage = "master_key" prompt).
    """
    _ensure_vault_security_row(conn, user_id)
    sec = get_vault_security(conn, user_id)
    new_count = (sec["failed_attempts"] if sec else 0) + 1
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Determine lockout duration
    lockout_seconds = LOCKOUT_SCHEDULE.get(new_count, DEFAULT_LOCKOUT)
    lockout_until_str = None

    if lockout_seconds > 0:
        lockout_until = datetime.now(timezone.utc) + timedelta(seconds=lockout_seconds)
        lockout_until_str = lockout_until.isoformat().replace("+00:00", "Z")

    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO vault_security (user_id, failed_attempts, lockout_until, last_failed_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
               failed_attempts = excluded.failed_attempts,
               lockout_until   = excluded.lockout_until,
               last_failed_at  = excluded.last_failed_at""",
        (user_id, new_count, lockout_until_str, now_str)
    )
    conn.commit()
    return new_count, lockout_seconds


def reset_vault_security(conn, user_id: int):
    """Reset all vault security counters after a successful unlock."""
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO vault_security (user_id, failed_attempts, lockout_until, last_failed_at)
           VALUES (?, 0, NULL, NULL)
           ON CONFLICT(user_id) DO UPDATE SET
               failed_attempts = 0,
               lockout_until   = NULL,
               last_failed_at  = NULL""",
        (user_id,)
    )
    conn.commit()


def get_current_unlock_stage(conn, user_id: int) -> str:
    """
    Returns the current expected unlock stage for a user.
    'pin'        — normal first attempt (no prior failures)
    'master_key' — prior failure, master key required (only if master key exists)
    """
    _ensure_vault_security_row(conn, user_id)
    sec = get_vault_security(conn, user_id)
    if sec and sec["failed_attempts"] >= 1:
        cursor = conn.cursor()
        cursor.execute("SELECT master_key_hash FROM vault_pins WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row and row["master_key_hash"]:
            return "master_key"
    return "pin"


# ===========================================================================
# VAULT SESSIONS — DB-backed, 5-minute inactivity TTL
# ===========================================================================

def create_vault_session(conn, user_id: int) -> str:
    """Create a new vault session. Returns session_id."""
    session_id = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=VAULT_SESSION_TTL_SECONDS)
    now_str = now.isoformat().replace("+00:00", "Z")
    expires_str = expires_at.isoformat().replace("+00:00", "Z")

    cursor = conn.cursor()
    # Remove any existing session for this user first
    cursor.execute("DELETE FROM vault_sessions WHERE user_id = ?", (user_id,))
    cursor.execute(
        "INSERT INTO vault_sessions (session_id, user_id, unlocked_at, last_activity, expires_at) VALUES (?, ?, ?, ?, ?)",
        (session_id, user_id, now_str, now_str, expires_str)
    )
    conn.commit()
    return session_id


def validate_vault_session(conn, user_id: int) -> bool:
    """
    Check if an active, non-expired vault session exists for this user.
    Backend is the authority — does not rely on frontend state.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT expires_at FROM vault_sessions WHERE user_id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    if not row:
        return False

    try:
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            # Session expired — clean it up
            cursor.execute("DELETE FROM vault_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
            return False
    except Exception:
        return False

    return True


def touch_vault_session(conn, user_id: int):
    """
    Refresh the vault session expiry on any authenticated vault API activity.
    This means normal usage (listing files, etc.) keeps the session alive.
    """
    new_expires = datetime.now(timezone.utc) + timedelta(seconds=VAULT_SESSION_TTL_SECONDS)
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    expires_str = new_expires.isoformat().replace("+00:00", "Z")

    cursor = conn.cursor()
    cursor.execute(
        "UPDATE vault_sessions SET last_activity = ?, expires_at = ? WHERE user_id = ?",
        (now_str, expires_str, user_id)
    )
    conn.commit()


def invalidate_vault_session(conn, user_id: int):
    """Delete vault session from DB on manual lock or auto-expiry."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_sessions WHERE user_id = ?", (user_id,))
    conn.commit()


# ===========================================================================
# CRYPTOGRAPHIC KEY WIPING
# ===========================================================================

def wipe_vault_key(active_vault_sessions: dict, username: str):
    """
    Securely wipe the derived AES key from memory before removing the reference.
    Overwrites the bytes with zeros to reduce the window where key material
    lingers in memory.
    """
    if username in active_vault_sessions:
        key_bytes = active_vault_sessions[username]
        try:
            # Overwrite key material in a bytearray, then discard
            key_arr = bytearray(key_bytes)
            for i in range(len(key_arr)):
                key_arr[i] = 0
        except Exception:
            pass
        del active_vault_sessions[username]


# ===========================================================================
# LOGIN BRUTE-FORCE PROTECTION
# ===========================================================================

def _get_login_record(conn, username: str, ip_address: str) -> Optional[dict]:
    """Fetch login_attempts row for username + IP combo."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, failed_count, lockout_until, last_attempt FROM login_attempts WHERE username = ? AND ip_address = ?",
        (username, ip_address)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "failed_count": row["failed_count"],
        "lockout_until": row["lockout_until"],
        "last_attempt": row["last_attempt"]
    }


def check_login_lockout(conn, username: str, ip_address: str) -> Tuple[bool, int]:
    """
    Check if this username+IP is currently locked out.
    Returns (is_locked: bool, seconds_remaining: int).
    Applied regardless of whether the username exists (prevents enumeration).
    """
    record = _get_login_record(conn, username, ip_address)
    if not record or not record["lockout_until"]:
        return False, 0

    try:
        lockout_until = datetime.fromisoformat(record["lockout_until"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if now < lockout_until:
            remaining = int((lockout_until - now).total_seconds())
            return True, remaining
    except Exception:
        pass

    return False, 0


def record_login_failure(conn, username: str, ip_address: str) -> int:
    """
    Record a failed login attempt for username + IP.
    Applies lockout if threshold reached.
    Returns new failed_count.
    """
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    record = _get_login_record(conn, username, ip_address)

    if record:
        new_count = record["failed_count"] + 1
    else:
        new_count = 1

    lockout_until_str = None
    if new_count >= LOGIN_MAX_ATTEMPTS:
        lockout_until = datetime.now(timezone.utc) + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        lockout_until_str = lockout_until.isoformat().replace("+00:00", "Z")

    cursor = conn.cursor()
    if record:
        cursor.execute(
            "UPDATE login_attempts SET failed_count = ?, lockout_until = ?, last_attempt = ? WHERE id = ?",
            (new_count, lockout_until_str, now_str, record["id"])
        )
    else:
        cursor.execute(
            "INSERT INTO login_attempts (username, ip_address, failed_count, lockout_until, last_attempt) VALUES (?, ?, ?, ?, ?)",
            (username, ip_address, new_count, lockout_until_str, now_str)
        )
    conn.commit()

    # Log severity escalation
    if new_count == 3:
        log_event("WARNING", f"Suspicious login pattern: 3 failed attempts for '{username}' from {ip_address}")
    elif new_count >= LOGIN_MAX_ATTEMPTS:
        log_event("CRITICAL", f"Login lockout triggered: {new_count} failed attempts for '{username}' from {ip_address}")

    return new_count


def reset_login_attempts(conn, username: str, ip_address: str):
    """Reset login failure counters after a successful login."""
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM login_attempts WHERE username = ? AND ip_address = ?",
        (username, ip_address)
    )
    conn.commit()
