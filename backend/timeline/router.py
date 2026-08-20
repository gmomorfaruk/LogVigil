from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import sqlite3

from db import get_db
from network.router import get_network_alerts
from integrity.router import get_integrity_alerts

router = APIRouter(prefix="/api/timeline", tags=["Timeline"])

class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    event_type: str
    message: str
    severity: str

@router.get("", response_model=List[TimelineEvent])
def get_timeline():
    events = []
    
    # 1. Fetch Audit Logs
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, level, message FROM audit_logs")
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            msg = row["message"]
            msg_lower = msg.lower()
            if "firewall" in msg_lower:
                event_type = "FIREWALL"
            elif "vault" in msg_lower or "decrypt" in msg_lower or "encrypt" in msg_lower or "credentials" in msg_lower or "pin" in msg_lower:
                event_type = "VAULT"
            else:
                event_type = "SYSTEM"
                
            events.append({
                "id": f"audit_{row['id']}",
                "timestamp": row["timestamp"],
                "event_type": event_type,
                "message": msg,
                "severity": row["level"]
            })
    except Exception:
        pass
        
    # 2. Fetch File Integrity Alerts
    try:
        integrity_alerts = get_integrity_alerts()
        for alert in integrity_alerts:
            # Handle both dictionary and object representations (for routing vs. direct function invocation)
            alert_id = alert.get("id") if isinstance(alert, dict) else getattr(alert, "id", "")
            file_path = alert.get("file_path") if isinstance(alert, dict) else getattr(alert, "file_path", "")
            alert_type = alert.get("alert_type") if isinstance(alert, dict) else getattr(alert, "alert_type", "")
            detected_at = alert.get("detected_at") if isinstance(alert, dict) else getattr(alert, "detected_at", "")
            
            events.append({
                "id": f"integrity_{alert_id}",
                "timestamp": detected_at,
                "event_type": "INTEGRITY",
                "message": f"File integrity breach: {file_path} ({alert_type})",
                "severity": "WARNING"
            })
    except Exception:
        pass
        
    # 3. Fetch Network Alerts
    try:
        net_alerts = get_network_alerts()
        for alert in net_alerts:
            alert_id = alert.get("id") if isinstance(alert, dict) else getattr(alert, "id", "")
            message = alert.get("message") if isinstance(alert, dict) else getattr(alert, "message", "")
            category = alert.get("category") if isinstance(alert, dict) else getattr(alert, "category", "")
            timestamp = alert.get("timestamp") if isinstance(alert, dict) else getattr(alert, "timestamp", "")
            risk_level = alert.get("risk_level") if isinstance(alert, dict) else getattr(alert, "risk_level", "LOW")
            
            events.append({
                "id": f"network_{alert_id}",
                "timestamp": timestamp,
                "event_type": "NETWORK",
                "message": f"Network threat detected: {message} ({category})",
                "severity": risk_level
            })
    except Exception:
        pass
        
    # Sort events descending by timestamp
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events
