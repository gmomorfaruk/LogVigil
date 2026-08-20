import os
import hashlib
import sqlite3
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from db import get_db
from logger import log_event

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
