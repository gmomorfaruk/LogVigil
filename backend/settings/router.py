import os
import shutil
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from db import DB_PATH, DB_DIR, get_db, init_db
from logger import log_event

router = APIRouter(prefix="/api/settings", tags=["Settings"])

BACKUP_DIR = os.path.join(DB_DIR, "backups")
BACKUP_PATH = DB_PATH + ".bak"

# ---------------------------------------------------------------------------
# Background Backup Scheduler Task
# ---------------------------------------------------------------------------

scheduler_task: Optional[asyncio.Task] = None

def execute_db_backup(trigger_reason: str = "MANUAL") -> str:
    """
    Copies the active SQLite database to BACKUP_PATH and a timestamped snapshot
    in database/backups/. Updates last_backup_time in DB settings.
    Returns the backup filename.
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError("Active database file not found.")

    os.makedirs(BACKUP_DIR, exist_ok=True)

    # 1. Overwrite primary .bak file
    shutil.copy2(DB_PATH, BACKUP_PATH)

    # 2. Save timestamped snapshot in database/backups/
    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y%m%d_%H%M%S")
    snapshot_filename = f"securevault_backup_{timestamp_str}.db"
    snapshot_path = os.path.join(BACKUP_DIR, snapshot_filename)
    shutil.copy2(DB_PATH, snapshot_path)

    # 3. Update last_backup_time in DB
    now_iso = now.isoformat().replace("+00:00", "Z")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO system_settings (key, value) VALUES ('last_backup_time', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = ?",
        (now_iso, now_iso)
    )
    conn.commit()
    conn.close()

    log_event("INFO", f"Database backup created successfully ({trigger_reason}): {snapshot_filename}")
    return snapshot_filename


async def background_backup_loop():
    """
    Background worker that runs every 60 seconds.
    Checks if an automated backup is due based on backup_frequency and auto_update flag.
    """
    log_event("INFO", "Automated Database Backup Scheduler initialized.")
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM system_settings")
            settings = {row["key"]: row["value"] for row in cursor.fetchall()}
            conn.close()

            auto_update = settings.get("auto_update", "false").lower() == "true"
            frequency = settings.get("backup_frequency", "WEEKLY").upper()
            last_backup_iso = settings.get("last_backup_time", "")

            # If auto_update/auto_backup is enabled
            if auto_update:
                is_due = False
                now = datetime.now(timezone.utc)

                if not last_backup_iso:
                    is_due = True
                else:
                    try:
                        last_backup = datetime.fromisoformat(last_backup_iso.replace("Z", "+00:00"))
                        if frequency == "DAILY" and (now - last_backup) >= timedelta(days=1):
                            is_due = True
                        elif frequency == "WEEKLY" and (now - last_backup) >= timedelta(weeks=1):
                            is_due = True
                        elif frequency == "MONTHLY" and (now - last_backup) >= timedelta(days=30):
                            is_due = True
                    except Exception:
                        is_due = True

                if is_due:
                    execute_db_backup(trigger_reason=f"AUTO-{frequency}")
        except asyncio.CancelledError:
            log_event("INFO", "Automated Backup Scheduler background task stopped.")
            break
        except Exception as e:
            log_event("WARNING", f"Background backup scheduler loop error: {str(e)}")
            await asyncio.sleep(60)


def start_scheduler():
    global scheduler_task
    if scheduler_task is None or scheduler_task.done():
        scheduler_task = asyncio.create_task(background_backup_loop())


def stop_scheduler():
    global scheduler_task
    if scheduler_task and not scheduler_task.done():
        scheduler_task.cancel()

# ---------------------------------------------------------------------------
# Pydantic Schemas & Endpoints
# ---------------------------------------------------------------------------

class SystemSettings(BaseModel):
    dark_mode: bool
    notifications_enabled: bool
    auto_update: bool
    backup_frequency: str
    last_backup_time: Optional[str] = None

class BackupSnapshot(BaseModel):
    filename: str
    size_bytes: int
    created_at: str

@router.get("", response_model=SystemSettings)
def get_settings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM system_settings")
    rows = cursor.fetchall()
    conn.close()

    settings_dict = {row["key"]: row["value"] for row in rows}
    return {
        "dark_mode": settings_dict.get("dark_mode", "true").lower() == "true",
        "notifications_enabled": settings_dict.get("notifications_enabled", "true").lower() == "true",
        "auto_update": settings_dict.get("auto_update", "false").lower() == "true",
        "backup_frequency": settings_dict.get("backup_frequency", "WEEKLY"),
        "last_backup_time": settings_dict.get("last_backup_time", None)
    }

@router.post("", response_model=SystemSettings)
def update_settings(req: SystemSettings):
    conn = get_db()
    cursor = conn.cursor()
    
    settings_tuples = [
        ("dark_mode", "true" if req.dark_mode else "false"),
        ("notifications_enabled", "true" if req.notifications_enabled else "false"),
        ("auto_update", "true" if req.auto_update else "false"),
        ("backup_frequency", req.backup_frequency)
    ]

    for key, value in settings_tuples:
        cursor.execute(
            "INSERT INTO system_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = ?",
            (key, value, value)
        )
    conn.commit()
    conn.close()

    log_event("INFO", f"System settings updated. Auto-sync: {req.auto_update}, Frequency: {req.backup_frequency}")
    return get_settings()

@router.post("/backup")
def backup_database():
    try:
        filename = execute_db_backup(trigger_reason="MANUAL")
        return {"message": "Database backup created successfully.", "filename": filename}
    except Exception as e:
        log_event("ERROR", f"Failed to backup database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database backup failed: {str(e)}")

@router.post("/restore")
def restore_database(filename: Optional[str] = None):
    try:
        source_path = BACKUP_PATH
        if filename:
            target_snapshot = os.path.join(BACKUP_DIR, filename)
            if os.path.exists(target_snapshot):
                source_path = target_snapshot

        if not os.path.exists(source_path):
            raise HTTPException(status_code=404, detail="Backup file not found. Perform a backup first.")

        import sqlite3
        src_conn = sqlite3.connect(source_path)
        dest_conn = sqlite3.connect(DB_PATH)
        try:
            with dest_conn:
                src_conn.backup(dest_conn)
        finally:
            src_conn.close()
            dest_conn.close()
        
        init_db()
        log_event("INFO", f"Database state restored from backup source ({os.path.basename(source_path)}) successfully.")
        return {"message": "Database restored successfully."}
    except Exception as e:
        log_event("ERROR", f"Failed to restore database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database restore failed: {str(e)}")

@router.get("/backups", response_model=List[BackupSnapshot])
def list_backups():
    """Returns all available timestamped backup snapshots."""
    snapshots = []
    if os.path.exists(BACKUP_DIR):
        for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if fname.endswith(".db"):
                fpath = os.path.join(BACKUP_DIR, fname)
                mtime = os.path.getmtime(fpath)
                created_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                snapshots.append({
                    "filename": fname,
                    "size_bytes": os.path.getsize(fpath),
                    "created_at": created_iso
                })
    return snapshots
