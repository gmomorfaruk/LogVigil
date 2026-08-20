from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from db import get_db

router = APIRouter(prefix="/api/logs", tags=["Logs"])

class LogEntry(BaseModel):
    id: int
    timestamp: str
    level: str
    message: str
    operator: Optional[str]

@router.get("", response_model=List[LogEntry])
def get_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, level, message, operator FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "level": row["level"],
            "message": row["message"],
            "operator": row["operator"]
        } for row in rows
    ]
