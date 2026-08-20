from fastapi import APIRouter
from pydantic import BaseModel
import sqlite3

from firewall.router import firewall_state
from vault.router import vault_state
from integrity.router import monitored_folders, mock_alerts as integrity_alerts
from network.router import network_state, mock_alerts as network_alerts
from db import get_db

router = APIRouter(prefix="/api/security-score", tags=["Security Score"])

class ScoreBreakdown(BaseModel):
    firewall_score: int
    vault_score: int
    integrity_score: int
    network_score: int
    password_score: int

class SecurityScoreResponse(BaseModel):
    overall_score: int
    breakdown: ScoreBreakdown

@router.get("", response_model=SecurityScoreResponse)
def get_security_score():
    # 1. Firewall Score: 100 if enabled, 30 if disabled
    fw_enabled = firewall_state.get("enabled", False)
    firewall_score = 100 if fw_enabled else 30

    # 2. Vault Score: 100 if locked (secure), 60 if unlocked
    vault_locked = vault_state.get("locked", True)
    vault_score = 100 if vault_locked else 60

    # 3. Integrity Score: 100 - 20 * alerts (min 0), or 50 if no folders monitored
    if not monitored_folders:
        integrity_score = 50
    else:
        integrity_score = max(0, 100 - (20 * len(integrity_alerts)))

    # 4. Network Score: 100 - 10 * alerts (min 0) if active, 40 if inactive
    net_active = network_state.get("active", False)
    if net_active:
        network_score = max(0, 100 - (10 * len(network_alerts)))
    else:
        network_score = 40

    # 5. Password Score: 90 if users registered in DB, 0 if empty
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        row = cursor.fetchone()
        user_count = row["count"] if row else 0
        conn.close()
    except Exception:
        user_count = 0
    
    password_score = 90 if user_count > 0 else 0

    # Compute overall score as the average of components
    overall_score = int((firewall_score + vault_score + integrity_score + network_score + password_score) / 5)

    return {
        "overall_score": overall_score,
        "breakdown": {
            "firewall_score": firewall_score,
            "vault_score": vault_score,
            "integrity_score": integrity_score,
            "network_score": network_score,
            "password_score": password_score
        }
    }

