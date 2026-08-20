import logging
import os
from datetime import datetime, timezone
from db import get_db

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOGS_DIR, "logvigil.log")

logger = logging.getLogger("LogVigil")
logger.setLevel(logging.INFO)

# Setup handler and format explicitly to prevent conflicts with root configuration
if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

def log_event(level: str, message: str, operator: str = None):
    """
    Logs an event to the standard file/console, and persists it into the SQLite audit_logs table.
    """
    lvl = level.upper()
    if lvl == "DEBUG":
        logger.debug(message)
    elif lvl in ("WARNING", "WARN"):
        logger.warning(message)
    elif lvl == "ERROR":
        logger.error(message)
    else:
        logger.info(message)

    try:
        conn = get_db()
        cursor = conn.cursor()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        cursor.execute(
            "INSERT INTO audit_logs (timestamp, level, message, operator) VALUES (?, ?, ?, ?)",
            (timestamp, lvl, message, operator)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save log to SQLite database: {str(e)}")
