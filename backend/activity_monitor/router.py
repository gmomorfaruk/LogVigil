"""
Activity Monitor API Router — Phase 15
Endpoints for querying activity logs, toggling monitoring, and getting summaries.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone

from db import get_db
from logger import log_event
from activity_monitor.daemon import (
    is_monitor_running,
    force_start_monitor,
    force_stop_monitor,
)

router = APIRouter(prefix="/api/activity", tags=["Activity Monitor"])


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class ActivityLogEntry(BaseModel):
    id: int
    timestamp: str
    event_type: str
    target: str
    details: Optional[str] = None
    pid: Optional[int] = None
    username: Optional[str] = None


class ActivityLogsResponse(BaseModel):
    total: int
    logs: List[ActivityLogEntry]


class ActivitySummary(BaseModel):
    total_events: int
    unique_apps: int
    top_apps: list
    events_by_hour: list
    monitoring_since: Optional[str] = None


class MonitorStatus(BaseModel):
    enabled: bool
    running: bool
    poll_interval: int
    total_logs: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=MonitorStatus)
def get_monitor_status():
    """Get current activity monitor status."""
    conn = get_db()
    cursor = conn.cursor()

    # Read settings
    cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_monitor_enabled'")
    row = cursor.fetchone()
    enabled = row["value"].lower() == "true" if row else False

    cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_poll_interval'")
    row = cursor.fetchone()
    poll_interval = int(row["value"]) if row else 5

    # Count total logs
    cursor.execute("SELECT COUNT(*) as count FROM activity_logs")
    total_logs = cursor.fetchone()["count"]

    conn.close()

    return {
        "enabled": enabled,
        "running": is_monitor_running(),
        "poll_interval": poll_interval,
        "total_logs": total_logs,
    }


@router.post("/toggle")
async def toggle_monitor():
    """Enable or disable the activity monitor."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_monitor_enabled'")
    row = cursor.fetchone()
    current_val = row["value"].lower() if row else "false"

    if current_val == "true":
        # Disable
        new_val = "false"
        cursor.execute(
            "INSERT INTO system_settings (key, value) VALUES ('activity_monitor_enabled', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = ?",
            (new_val, new_val)
        )
        conn.commit()
        conn.close()
        force_stop_monitor()
        log_event("INFO", "Activity Monitor disabled by operator.")
        return {"enabled": False, "running": False, "message": "Activity Monitor disabled."}
    else:
        # Enable
        new_val = "true"
        cursor.execute(
            "INSERT INTO system_settings (key, value) VALUES ('activity_monitor_enabled', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = ?",
            (new_val, new_val)
        )
        conn.commit()
        conn.close()
        force_start_monitor()
        log_event("INFO", "Activity Monitor enabled by operator.")
        return {"enabled": True, "running": True, "message": "Activity Monitor enabled."}


@router.get("/logs", response_model=ActivityLogsResponse)
def get_activity_logs(
    event_type: Optional[str] = Query(None, description="Filter by APP_OPENED or APP_CLOSED"),
    search: Optional[str] = Query(None, description="Search by app name"),
    date_from: Optional[str] = Query(None, description="ISO date start filter"),
    date_to: Optional[str] = Query(None, description="ISO date end filter"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query activity logs with optional filters."""
    conn = get_db()
    cursor = conn.cursor()

    # Build query dynamically
    conditions = []
    params = []

    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type.upper())

    if search:
        conditions.append("target LIKE ?")
        params.append(f"%{search}%")

    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)

    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get total count
    cursor.execute(f"SELECT COUNT(*) as count FROM activity_logs WHERE {where_clause}", params)
    total = cursor.fetchone()["count"]

    # Get paginated results
    cursor.execute(
        f"SELECT * FROM activity_logs WHERE {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    )
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "target": row["target"],
            "details": row["details"],
            "pid": row["pid"],
            "username": row["username"],
        })

    return {"total": total, "logs": logs}


@router.get("/logs/summary", response_model=ActivitySummary)
def get_activity_summary():
    """Get aggregated activity summary."""
    conn = get_db()
    cursor = conn.cursor()

    # Total events
    cursor.execute("SELECT COUNT(*) as count FROM activity_logs")
    total_events = cursor.fetchone()["count"]

    # Unique apps
    cursor.execute("SELECT COUNT(DISTINCT target) as count FROM activity_logs WHERE event_type = 'APP_OPENED'")
    unique_apps = cursor.fetchone()["count"]

    # Top apps (by open count)
    cursor.execute(
        "SELECT target as name, COUNT(*) as open_count FROM activity_logs "
        "WHERE event_type = 'APP_OPENED' GROUP BY target ORDER BY open_count DESC LIMIT 10"
    )
    top_apps = [{"name": row["name"], "open_count": row["open_count"]} for row in cursor.fetchall()]

    # Events by hour (last 24 hours)
    cursor.execute(
        "SELECT substr(timestamp, 12, 2) as hour, COUNT(*) as count "
        "FROM activity_logs "
        "WHERE timestamp >= datetime('now', '-1 day') "
        "GROUP BY hour ORDER BY hour"
    )
    events_by_hour = [{"hour": f"{row['hour']}:00", "count": row["count"]} for row in cursor.fetchall()]

    # Earliest log entry
    cursor.execute("SELECT MIN(timestamp) as earliest FROM activity_logs")
    row = cursor.fetchone()
    monitoring_since = row["earliest"] if row and row["earliest"] else None

    conn.close()

    return {
        "total_events": total_events,
        "unique_apps": unique_apps,
        "top_apps": top_apps,
        "events_by_hour": events_by_hour,
        "monitoring_since": monitoring_since,
    }


@router.delete("/logs")
def clear_activity_logs():
    """Clear all activity logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM activity_logs")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    log_event("INFO", f"Activity Monitor: operator cleared {deleted} log(s).")
    return {"message": f"Cleared {deleted} activity log(s).", "deleted": deleted}
