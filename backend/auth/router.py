from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, Field
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from db import get_db
from auth_service import hash_password, verify_password
from logger import log_event
from security_service import check_login_lockout, record_login_failure, reset_login_attempts, LOGIN_MAX_ATTEMPTS

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Session duration: 24 hours
SESSION_DURATION_HOURS = 24

class UserAuth(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1)

# ---------------------------------------------------------------------------
# Session helpers (DB-backed)
# ---------------------------------------------------------------------------

def _create_session(username: str) -> str:
    """Create a new session token, persist in DB, return the token."""
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=SESSION_DURATION_HOURS)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, username, now.isoformat().replace("+00:00", "Z"), expires.isoformat().replace("+00:00", "Z"))
    )
    conn.commit()
    conn.close()
    return token


def _validate_session(token: str) -> Optional[str]:
    """
    Validate a session token against the DB.
    Returns the username if valid, None if expired or not found.
    Cleans up expired sessions on each call.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Clean up expired sessions
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.commit()

    # Look up the token
    cursor.execute("SELECT username, expires_at FROM sessions WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # Double-check expiry (in case of clock drift)
    try:
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            return None
    except Exception:
        pass

    return row["username"]


def _destroy_session(token: str) -> Optional[str]:
    """Remove a session from DB. Returns the username if found."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sessions WHERE token = ?", (token,))
    row = cursor.fetchone()
    username = row["username"] if row else None

    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return username


# ---------------------------------------------------------------------------
# Backward compatibility: active_sessions proxy for vault/router.py fallback
# ---------------------------------------------------------------------------

class _SessionProxy(dict):
    """
    Dict-like proxy that reads from the DB sessions table.
    Allows `active_sessions.get(token)` to still work from vault/router.py.
    """
    def get(self, token, default=None):
        result = _validate_session(token)
        return result if result is not None else default

    def __contains__(self, token):
        return _validate_session(token) is not None

    def __getitem__(self, token):
        result = _validate_session(token)
        if result is None:
            raise KeyError(token)
        return result

    def __delitem__(self, token):
        _destroy_session(token)

active_sessions = _SessionProxy()

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register")
def register(user: UserAuth):
    username = user.username.strip()
    password = user.password

    if not username:
        log_event("WARNING", "Registration failed: Empty username submitted")
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    conn = get_db()
    cursor = conn.cursor()

    # Check duplicate user
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        log_event("WARNING", f"Registration failed: Operator '{username}' already exists")
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash password with secure PBKDF2 algorithm
    pwd_hash, salt = hash_password(password)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, pwd_hash, salt)
        )
        conn.commit()
        log_event("INFO", f"Operator registered successfully: '{username}'")
    except Exception as e:
        conn.close()
        log_event("ERROR", f"Registration database error for user '{username}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    conn.close()
    return {"message": "Registration successful"}


@router.post("/login")
def login(user: UserAuth, request: Request):
    username = user.username.strip()
    password = user.password

    # Extract client IP for brute-force tracking
    forwarded = request.headers.get("X-Forwarded-For")
    ip_address = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    conn = get_db()

    # --- Check lockout BEFORE looking up user (prevents username enumeration timing) ---
    is_locked, secs_remaining = check_login_lockout(conn, username, ip_address)
    if is_locked:
        conn.close()
        minutes = (secs_remaining + 59) // 60
        raise HTTPException(
            status_code=429,
            detail=f"Access temporarily restricted. Try again in {minutes} minute(s).",
            headers={"X-Lockout-Seconds": str(secs_remaining)}
        )

    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    # --- Generic failure path (same message whether user missing or wrong password) ---
    if not row or not verify_password(password, row["salt"], row["password_hash"]):
        new_count = record_login_failure(conn, username, ip_address)
        conn.close()

        # Log severity escalation (internal only — not exposed to caller)
        if not row:
            log_event("WARNING", f"Failed login attempt: Username '{username}' not found (IP: {ip_address})")
        else:
            log_event("WARNING", f"Failed login attempt: Incorrect password for operator '{username}' (IP: {ip_address})")

        # Always return the same generic message to prevent enumeration
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # --- Successful login ---
    reset_login_attempts(conn, username, ip_address)
    conn.close()

    # Create persistent DB session
    token = _create_session(username)

    log_event("INFO", f"Operator session established for: '{username}'", operator=username)

    return {
        "message": "Login successful",
        "token": token,
        "username": username
    }


@router.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        log_event("WARNING", "Logout attempt failed: Invalid authorization header format")
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.split(" ")[1]
    username = _destroy_session(token)

    if username:
        log_event("INFO", f"Operator session terminated for: '{username}'", operator=username)
    else:
        log_event("WARNING", "Logout attempt failed: Session token not found or already expired")

    return {"message": "Logged out successfully"}


@router.get("/me")
def get_me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ")[1]
    username = _validate_session(token)

    if not username:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    return {
        "username": username,
        "authenticated": True
    }
