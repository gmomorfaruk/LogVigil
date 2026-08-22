import os
import hashlib
import sqlite3
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from db import get_db
from logger import log_event
from integrity.key_locker import generate_keypair, lock_file, verify_file_integrity

router = APIRouter(prefix="/api/integrity", tags=["File Integrity"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_sha256(file_path: str) -> Optional[str]:
    """
    Compute the SHA-256 hex digest of a file.
    Returns None if the file cannot be read.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64 KB chunks for large file support
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def walk_folder(folder_path: str):
    """
    Walk a directory tree and yield (file_path, file_size) for every regular file.
    Silently skips files/dirs that cannot be accessed.
    """
    for root, _dirs, files in os.walk(folder_path, followlinks=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if os.path.isfile(fpath):
                    yield fpath, os.path.getsize(fpath)
            except (OSError, PermissionError):
                continue

# ---------------------------------------------------------------------------
# Backward-compatible exports for security_score and timeline routers
# ---------------------------------------------------------------------------

def _get_monitored_folders_from_db() -> List[str]:
    """Return a deduplicated list of monitored folder paths from the DB."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT folder_path FROM integrity_baselines")
        folders = [row["folder_path"] for row in cursor.fetchall()]
        conn.close()
        return folders
    except Exception:
        return []


def _get_alerts_from_db() -> list:
    """Return all integrity alerts from the DB as dicts."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, file_path, alert_type, hash_old, hash_new, detected_at FROM integrity_alerts ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "id": f"alert_{row['id']:03d}",
                "file_path": row["file_path"],
                "alert_type": row["alert_type"],
                "hash_old": row["hash_old"] or "",
                "hash_new": row["hash_new"] or "",
                "detected_at": row["detected_at"]
            }
            for row in rows
        ]
    except Exception:
        return []


class _MonitoredFolderProxy:
    """
    A list-like proxy so that `from integrity.router import monitored_folders`
    in security_score/router.py keeps working. Reads from DB on every access.
    """
    def __len__(self):
        return len(_get_monitored_folders_from_db())

    def __iter__(self):
        return iter(_get_monitored_folders_from_db())

    def __bool__(self):
        return len(self) > 0

    def __getitem__(self, idx):
        return _get_monitored_folders_from_db()[idx]


# These names are imported by security_score/router.py and timeline/router.py
monitored_folders = _MonitoredFolderProxy()
mock_alerts = _get_alerts_from_db  # callable; security_score uses len(mock_alerts)


class _AlertsLenProxy:
    """Proxy so len(mock_alerts) keeps working for security_score."""
    def __len__(self):
        return len(_get_alerts_from_db())

    def __iter__(self):
        return iter(_get_alerts_from_db())

    def __bool__(self):
        return len(self) > 0


mock_alerts = _AlertsLenProxy()

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class IntegrityStatusResponse(BaseModel):
    monitored_folders: List[str]
    protected_files_count: int
    modified_files_count: int

class MonitorFolderRequest(BaseModel):
    folder_path: str = Field(..., min_length=1)

class IntegrityAlert(BaseModel):
    id: str
    file_path: str
    alert_type: str
    hash_old: str
    hash_new: str
    detected_at: str

class ScanResultResponse(BaseModel):
    scanned_files: int
    new_alerts: int
    message: str

class MessageResponse(BaseModel):
    message: str

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=IntegrityStatusResponse)
def get_integrity_status():
    conn = get_db()
    cursor = conn.cursor()

    # Unique monitored folders
    cursor.execute("SELECT DISTINCT folder_path FROM integrity_baselines")
    folders = [row["folder_path"] for row in cursor.fetchall()]

    # Total baselined files
    cursor.execute("SELECT COUNT(*) as count FROM integrity_baselines")
    protected = cursor.fetchone()["count"]

    # Total unresolved alerts
    cursor.execute("SELECT COUNT(*) as count FROM integrity_alerts")
    modified = cursor.fetchone()["count"]

    conn.close()
    return {
        "monitored_folders": folders,
        "protected_files_count": protected,
        "modified_files_count": modified
    }


@router.post("/monitor", response_model=MessageResponse)
def monitor_folder(req: MonitorFolderRequest):
    folder_path = req.folder_path.strip()

    if not os.path.isdir(folder_path):
        log_event("WARNING", f"Integrity Monitor: Path '{folder_path}' is not a valid directory")
        raise HTTPException(status_code=400, detail="Path is not a valid directory on this system")

    conn = get_db()
    cursor = conn.cursor()

    # Check if already monitored
    cursor.execute("SELECT COUNT(*) as count FROM integrity_baselines WHERE folder_path = ?", (folder_path,))
    if cursor.fetchone()["count"] > 0:
        conn.close()
        log_event("WARNING", f"Folder monitoring request ignored: Folder '{folder_path}' already monitored")
        raise HTTPException(status_code=400, detail="Folder is already monitored")

    # Walk the folder and baseline every file
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    file_count = 0

    for fpath, fsize in walk_folder(folder_path):
        file_hash = compute_sha256(fpath)
        if file_hash is None:
            continue
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO integrity_baselines (folder_path, file_path, sha256_hash, file_size, baselined_at) VALUES (?, ?, ?, ?, ?)",
                (folder_path, fpath, file_hash, fsize, now)
            )
            file_count += 1
        except sqlite3.Error:
            continue

    conn.commit()
    conn.close()

    log_event("INFO", f"Folder added to File Integrity Monitor: '{folder_path}' ({file_count} files baselined)")
    return {"message": f"Successfully monitoring path: {folder_path} ({file_count} files baselined)"}


@router.delete("/monitor", response_model=MessageResponse)
def remove_monitored_folder(req: MonitorFolderRequest):
    folder_path = req.folder_path.strip()
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM integrity_baselines WHERE folder_path = ?", (folder_path,))
    if cursor.fetchone()["count"] == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Folder is not currently monitored")

    cursor.execute("DELETE FROM integrity_baselines WHERE folder_path = ?", (folder_path,))
    conn.commit()
    conn.close()

    log_event("INFO", f"Folder removed from File Integrity Monitor: '{folder_path}'")
    return {"message": f"Stopped monitoring path: {folder_path}"}


@router.post("/scan", response_model=ScanResultResponse)
def scan_integrity():
    """
    Re-scan all baselined files, compare current SHA256 vs stored hash.
    Generates alerts for MODIFIED, DELETED, and NEW files.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, folder_path, file_path, sha256_hash FROM integrity_baselines")
    baselines = cursor.fetchall()

    if not baselines:
        conn.close()
        return {"scanned_files": 0, "new_alerts": 0, "message": "No baselines to scan. Monitor a folder first."}

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    scanned = 0
    new_alerts = 0

    # Track which folder paths are involved for NEW file detection
    scanned_folders = set()

    for bl in baselines:
        fpath = bl["file_path"]
        old_hash = bl["sha256_hash"]
        folder = bl["folder_path"]
        scanned_folders.add(folder)
        scanned += 1

        if not os.path.exists(fpath):
            # File was DELETED
            try:
                cursor.execute(
                    "INSERT INTO integrity_alerts (file_path, alert_type, hash_old, hash_new, detected_at) VALUES (?, ?, ?, ?, ?)",
                    (fpath, "DELETED", old_hash, None, now)
                )
                new_alerts += 1
                cursor.execute(
                    "DELETE FROM integrity_baselines WHERE id = ?",
                    (bl["id"],)
                )
            except sqlite3.Error:
                pass
            continue

        current_hash = compute_sha256(fpath)
        if current_hash is None:
            continue

        if current_hash != old_hash:
            # File was MODIFIED
            try:
                cursor.execute(
                    "INSERT INTO integrity_alerts (file_path, alert_type, hash_old, hash_new, detected_at) VALUES (?, ?, ?, ?, ?)",
                    (fpath, "MODIFIED", old_hash, current_hash, now)
                )
                new_alerts += 1
            except sqlite3.Error:
                pass

            # Update baseline to the new hash
            cursor.execute(
                "UPDATE integrity_baselines SET sha256_hash = ?, baselined_at = ? WHERE id = ?",
                (current_hash, now, bl["id"])
            )

    # Detect NEW files in monitored folders (files not in baselines)
    cursor.execute("SELECT file_path FROM integrity_baselines")
    known_files = {row["file_path"] for row in cursor.fetchall()}

    for folder in scanned_folders:
        if not os.path.isdir(folder):
            continue
        for fpath, fsize in walk_folder(folder):
            if fpath not in known_files:
                new_hash = compute_sha256(fpath)
                if new_hash is None:
                    continue
                try:
                    cursor.execute(
                        "INSERT INTO integrity_alerts (file_path, alert_type, hash_old, hash_new, detected_at) VALUES (?, ?, ?, ?, ?)",
                        (fpath, "NEW", None, new_hash, now)
                    )
                    # Add to baselines automatically
                    cursor.execute(
                        "INSERT OR REPLACE INTO integrity_baselines (folder_path, file_path, sha256_hash, file_size, baselined_at) VALUES (?, ?, ?, ?, ?)",
                        (folder, fpath, new_hash, fsize, now)
                    )
                    new_alerts += 1
                    scanned += 1
                except sqlite3.Error:
                    continue

    conn.commit()
    conn.close()

    log_event("INFO", f"Integrity scan complete: {scanned} files scanned, {new_alerts} new alerts generated")
    return {
        "scanned_files": scanned,
        "new_alerts": new_alerts,
        "message": f"Scan complete. {scanned} files checked, {new_alerts} discrepancies detected."
    }


@router.get("/alerts", response_model=List[IntegrityAlert])
def get_integrity_alerts():
    return _get_alerts_from_db()


@router.delete("/alerts", response_model=MessageResponse)
def clear_integrity_alerts():
    """Clear all resolved integrity alerts."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM integrity_alerts")
    conn.commit()
    conn.close()
    log_event("INFO", "All integrity alerts cleared")
    return {"message": "All integrity alerts cleared"}


# ===========================================================================
# LOCK 3 — RSA-4096 + AES-256-GCM Private Key Protection
# ===========================================================================

class KeypairGenerateRequest(BaseModel):
    username: str = Field(..., min_length=1)
    passphrase: str = Field(..., min_length=8, description="Lock 3 passphrase (never stored)")

class KeypairStatusResponse(BaseModel):
    has_keypair: bool
    created_at: Optional[str]
    username: str

class Lock3EnableRequest(BaseModel):
    username: str = Field(..., min_length=1)
    file_path: str = Field(..., min_length=1)

class Lock3DisableRequest(BaseModel):
    username: str = Field(..., min_length=1)
    file_path: str = Field(..., min_length=1)

class Lock3VerifyRequest(BaseModel):
    username: str = Field(..., min_length=1)
    file_path: str = Field(..., min_length=1)
    passphrase: str = Field(..., min_length=1)

class Lock3VerifyResponse(BaseModel):
    file_path: str
    status: str   # UNMODIFIED | TAMPERED | DELETED | ERROR
    message: str

class Lock3FileEntry(BaseModel):
    file_path: str
    lv3_path: Optional[str]
    baseline_hash: str
    locked_at: Optional[str]

class Lock3StatusResponse(BaseModel):
    username: str
    has_keypair: bool
    locked_files: List[Lock3FileEntry]
    locked_count: int


@router.post("/keypair/generate", response_model=MessageResponse)
def generate_lock3_keypair(req: KeypairGenerateRequest):
    """
    Generate an RSA-4096 key pair for Lock 3 protection.
    The private key is encrypted with AES-256-GCM using the provided passphrase.
    The passphrase is NEVER stored — only the encrypted private key is kept.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Check if user already has a key pair
    cursor.execute("SELECT id FROM fim_keypairs WHERE username = ?", (req.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="A Lock 3 key pair already exists for this user. Delete it before regenerating."
        )

    try:
        public_pem, encrypted_private_hex, salt_hex = generate_keypair(req.passphrase)
    except Exception as e:
        conn.close()
        log_event("ERROR", f"Lock 3 key pair generation failed for '{req.username}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cursor.execute(
        "INSERT INTO fim_keypairs (username, public_key, private_key_enc, private_key_salt, created_at) VALUES (?, ?, ?, ?, ?)",
        (req.username, public_pem, encrypted_private_hex, salt_hex, now)
    )
    conn.commit()
    conn.close()

    log_event("INFO", f"Lock 3 RSA-4096 key pair generated for operator '{req.username}'", operator=req.username)
    return {"message": "Lock 3 key pair generated successfully. Store your passphrase securely — it cannot be recovered."}


@router.get("/keypair/status", response_model=KeypairStatusResponse)
def get_keypair_status(username: str):
    """Check whether a Lock 3 key pair exists for the given user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT created_at FROM fim_keypairs WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"has_keypair": True, "created_at": row["created_at"], "username": username}
    return {"has_keypair": False, "created_at": None, "username": username}


@router.post("/lock3/enable", response_model=MessageResponse)
def enable_lock3_on_file(req: Lock3EnableRequest):
    """
    Enable Lock 3 protection on any file.
    If the file is not yet in the FIM baseline, it is auto-baselined on the spot.
    Creates an encrypted .lv3 copy using the user's RSA-4096 public key.
    The original file is left in place; the .lv3 file is the protected encrypted copy.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Validate the file exists on disk first
    if not os.path.isfile(req.file_path):
        conn.close()
        raise HTTPException(status_code=404, detail=f"File not found on disk: {req.file_path}")

    # Fetch keypair (must exist)
    cursor.execute("SELECT public_key FROM fim_keypairs WHERE username = ?", (req.username,))
    kp_row = cursor.fetchone()
    if not kp_row:
        conn.close()
        raise HTTPException(status_code=404, detail="No Lock 3 key pair found. Generate one first.")

    # Check if the file is already in the FIM baseline
    cursor.execute(
        "SELECT id, sha256_hash, lock3_enabled FROM integrity_baselines WHERE file_path = ?",
        (req.file_path,)
    )
    bl_row = cursor.fetchone()

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if not bl_row:
        # Auto-baseline the file so it works without pre-monitoring its folder
        file_hash = compute_sha256(req.file_path)
        if file_hash is None:
            conn.close()
            raise HTTPException(status_code=500, detail="Cannot read file — check permissions.")
        file_size = os.path.getsize(req.file_path)
        folder_path = os.path.dirname(req.file_path)
        try:
            cursor.execute(
                "INSERT INTO integrity_baselines (folder_path, file_path, sha256_hash, file_size, baselined_at) VALUES (?, ?, ?, ?, ?)",
                (folder_path, req.file_path, file_hash, file_size, now)
            )
            conn.commit()
        except sqlite3.Error as e:
            conn.close()
            raise HTTPException(status_code=500, detail=f"Failed to baseline file: {str(e)}")
        # Re-fetch the new row
        cursor.execute(
            "SELECT id, sha256_hash, lock3_enabled FROM integrity_baselines WHERE file_path = ?",
            (req.file_path,)
        )
        bl_row = cursor.fetchone()
        log_event("INFO", f"File auto-baselined for Lock 3: '{req.file_path}'", operator=req.username)

    if bl_row["lock3_enabled"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Lock 3 is already enabled for this file.")

    try:
        lv3_path, plaintext_hash = lock_file(req.file_path, kp_row["public_key"])
    except Exception as e:
        conn.close()
        log_event("ERROR", f"Lock 3 encryption failed for '{req.file_path}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

    cursor.execute(
        "UPDATE integrity_baselines SET lock3_enabled = 1, lock3_path = ?, lock3_hash = ?, baselined_at = ? WHERE id = ?",
        (lv3_path, plaintext_hash, now, bl_row["id"])
    )

    conn.commit()
    conn.close()

    log_event("INFO", f"Lock 3 enabled on '{req.file_path}' → '{lv3_path}'", operator=req.username)
    return {"message": f"Lock 3 active. Encrypted copy saved at: {lv3_path}"}


@router.post("/lock3/disable", response_model=MessageResponse)
def disable_lock3_on_file(req: Lock3DisableRequest):
    """Remove Lock 3 protection from a file (deletes the .lv3 encrypted copy)."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, lock3_path, lock3_enabled FROM integrity_baselines WHERE file_path = ?",
        (req.file_path,)
    )
    bl_row = cursor.fetchone()
    if not bl_row or not bl_row["lock3_enabled"]:
        conn.close()
        raise HTTPException(status_code=404, detail="Lock 3 is not currently enabled for this file.")

    lv3_path = bl_row["lock3_path"]
    if lv3_path and os.path.isfile(lv3_path):
        try:
            os.remove(lv3_path)
        except OSError as e:
            conn.close()
            raise HTTPException(status_code=500, detail=f"Could not remove encrypted file: {str(e)}")

    cursor.execute(
        "UPDATE integrity_baselines SET lock3_enabled = 0, lock3_path = NULL, lock3_hash = NULL WHERE id = ?",
        (bl_row["id"],)
    )
    conn.commit()
    conn.close()

    log_event("INFO", f"Lock 3 disabled on '{req.file_path}'", operator=req.username)
    return {"message": f"Lock 3 removed from '{req.file_path}'."}


@router.post("/lock3/verify", response_model=Lock3VerifyResponse)
def verify_lock3_file(req: Lock3VerifyRequest):
    """
    Verify the integrity of a Lock 3 protected file.

    Flow:
      1. Fetch user's encrypted private key from DB
      2. Use passphrase to decrypt the private key (in memory only)
      3. Decrypt the .lv3 file (in memory only — never written to disk)
      4. SHA-256 the plaintext and compare to the stored baseline hash
      5. Return UNMODIFIED / TAMPERED / DELETED / ERROR

    The private key and decrypted content are wiped from memory after verification.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Fetch keypair
    cursor.execute(
        "SELECT private_key_enc, private_key_salt FROM fim_keypairs WHERE username = ?",
        (req.username,)
    )
    kp_row = cursor.fetchone()
    if not kp_row:
        conn.close()
        raise HTTPException(status_code=404, detail="No Lock 3 key pair found for this user.")

    # Fetch baseline
    cursor.execute(
        "SELECT lock3_path, lock3_hash, lock3_enabled FROM integrity_baselines WHERE file_path = ?",
        (req.file_path,)
    )
    bl_row = cursor.fetchone()
    conn.close()

    if not bl_row or not bl_row["lock3_enabled"]:
        raise HTTPException(status_code=404, detail="Lock 3 is not enabled for this file.")

    lv3_path = bl_row["lock3_path"]
    baseline_hash = bl_row["lock3_hash"]

    if not lv3_path or not baseline_hash:
        raise HTTPException(status_code=500, detail="Lock 3 metadata is incomplete. Re-enable Lock 3 on this file.")

    result = verify_file_integrity(
        lv3_path=lv3_path,
        baseline_sha256=baseline_hash,
        encrypted_private_hex=kp_row["private_key_enc"],
        salt_hex=kp_row["private_key_salt"],
        passphrase=req.passphrase
    )

    log_event(
        "INFO" if result["status"] == "UNMODIFIED" else "WARNING",
        f"Lock 3 integrity check for '{req.file_path}': {result['status']}",
        operator=req.username
    )
    return {"file_path": req.file_path, "status": result["status"], "message": result["message"]}


@router.get("/lock3/status", response_model=Lock3StatusResponse)
def get_lock3_status(username: str):
    """List all Lock 3 protected files and key pair status for a user."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT created_at FROM fim_keypairs WHERE username = ?", (username,))
    kp_row = cursor.fetchone()
    has_keypair = kp_row is not None

    cursor.execute(
        "SELECT file_path, lock3_path, lock3_hash, baselined_at FROM integrity_baselines WHERE lock3_enabled = 1"
    )
    rows = cursor.fetchall()
    conn.close()

    locked_files = [
        {
            "file_path": r["file_path"],
            "lv3_path": r["lock3_path"],
            "baseline_hash": r["lock3_hash"] or "",
            "locked_at": r["baselined_at"]
        }
        for r in rows
    ]

    return {
        "username": username,
        "has_keypair": has_keypair,
        "locked_files": locked_files,
        "locked_count": len(locked_files)
    }
