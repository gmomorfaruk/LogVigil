import json
import sqlite3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

from db import get_db
from logger import log_event
from network.router import get_network_alerts
from firewall.router import create_firewall_rule, FirewallRuleCreate, toggle_firewall, FirewallToggleRequest

router = APIRouter(prefix="/api/alerts", tags=["Threat Engine"])

class ThreatSummaryResponse(BaseModel):
    overall_risk: str
    total_alerts: int
    active_threats: int

class ThreatRecommendation(BaseModel):
    id: str
    threat_id: str
    title: str
    description: str
    action_type: str
    action_payload: Dict[str, Any]
    status: str

def sync_threat_recommendations():
    """
    Reads active network alerts, analyzes them, and populates the database
    with threat recommendations if they don't already exist.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        alerts = get_network_alerts()
    except Exception as e:
        log_event("WARNING", f"Threat Engine failed to fetch network alerts: {str(e)}")
        alerts = []
        
    # Get existing threat IDs already parsed
    cursor.execute("SELECT threat_id FROM threat_recommendations")
    existing_threat_ids = {row["threat_id"] for row in cursor.fetchall()}
    
    for alert in alerts:
        alert_id = alert["id"]
        if alert_id in existing_threat_ids:
            continue
            
        msg_upper = alert["message"].upper()
        category_upper = alert["category"].upper()
        risk_level = alert["risk_level"]
        src_ip = alert["source_ip"]
        
        if "MALWARE" in msg_upper or "MALWARE" in category_upper or risk_level == "HIGH":
            title = "Block Malicious Host IP"
            description = f"High-risk alert '{alert['message']}' detected. We recommend blocking outbound traffic to source IP {src_ip}."
            action_type = "FIREWALL_BLOCK"
            action_payload = {"ip": src_ip, "direction": "OUTBOUND"}
        elif "SQL INJECTION" in msg_upper or "SQL" in category_upper or risk_level == "MEDIUM":
            title = "Enable Inbound Port Block"
            description = "SQL Injection attempt detected on port 80. Ensure the firewall is enabled and monitoring traffic."
            action_type = "FIREWALL_ENABLE"
            action_payload = {}
        else:
            title = "Investigate Intrusion Alert"
            description = f"Unusual traffic alert: {alert['message']}. Review connection history for security risks."
            action_type = "FIREWALL_ENABLE"
            action_payload = {}

        cursor.execute("SELECT COUNT(*) as count FROM threat_recommendations")
        rec_count = cursor.fetchone()["count"]
        rec_id = f"rec_{rec_count + 1:03d}"
        
        cursor.execute(
            "INSERT INTO threat_recommendations (id, threat_id, title, description, action_type, action_payload, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rec_id, alert_id, title, description, action_type, json.dumps(action_payload), "PENDING")
        )
        conn.commit()
        log_event("INFO", f"Threat Engine generated recommendation '{rec_id}' for alert '{alert_id}'")
        
    conn.close()

@router.get("/summary", response_model=ThreatSummaryResponse)
def get_alerts_summary():
    sync_threat_recommendations()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, status, action_type FROM threat_recommendations")
    rows = cursor.fetchall()
    conn.close()
    
    total = len(rows)
    active = sum(1 for r in rows if r["status"] == "PENDING")
    
    # Calculate overall risk
    overall_risk = "LOW"
    for r in rows:
        if r["status"] == "PENDING":
            if r["action_type"] == "FIREWALL_BLOCK": # High risk
                overall_risk = "HIGH"
                break
            elif r["action_type"] == "FIREWALL_ENABLE":
                overall_risk = "MEDIUM"
                
    return {
        "overall_risk": overall_risk,
        "total_alerts": total,
        "active_threats": active
    }

@router.get("/recommendations", response_model=List[ThreatRecommendation])
def get_threat_recommendations():
    sync_threat_recommendations()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, threat_id, title, description, action_type, action_payload, status FROM threat_recommendations")
    rows = cursor.fetchall()
    conn.close()
    
    recs = []
    for r in rows:
        try:
            payload = json.loads(r["action_payload"])
        except Exception:
            payload = {}
        recs.append({
            "id": r["id"],
            "threat_id": r["threat_id"],
            "title": r["title"],
            "description": r["description"],
            "action_type": r["action_type"],
            "action_payload": payload,
            "status": r["status"]
        })
    return recs

@router.post("/recommendations/{rec_id}/apply")
def apply_recommendation(rec_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, action_type, action_payload, status FROM threat_recommendations WHERE id = ?", (rec_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        log_event("WARNING", f"Attempted to apply non-existent recommendation ID '{rec_id}'")
        raise HTTPException(status_code=404, detail="Recommendation not found")
        
    if row["status"] == "RESOLVED":
        conn.close()
        return {"message": f"Recommendation {rec_id} is already resolved."}
        
    action_type = row["action_type"]
    try:
        action_payload = json.loads(row["action_payload"])
    except Exception:
        action_payload = {}
        
    # Execute action programmatically
    success = False
    error_msg = ""
    try:
        if action_type == "FIREWALL_BLOCK":
            ip = action_payload.get("ip")
            if ip:
                rule_req = FirewallRuleCreate(
                    protocol="TCP",
                    port=443,
                    action="BLOCK",
                    direction="OUTBOUND",
                    ip_address=ip,
                    description=f"Threat Engine auto-block for IP {ip}"
                )
                create_firewall_rule(rule_req)
                success = True
            else:
                error_msg = "IP address missing in action payload"
        elif action_type == "FIREWALL_ENABLE":
            toggle_req = FirewallToggleRequest(enable=True)
            toggle_firewall(toggle_req)
            success = True
        else:
            error_msg = f"Unknown action type: {action_type}"
    except Exception as e:
        error_msg = str(e)
        
    if not success and error_msg:
        conn.close()
        log_event("ERROR", f"Failed to deploy countermeasure for recommendation '{rec_id}': {error_msg}")
        raise HTTPException(status_code=500, detail=f"Failed to execute countermeasure: {error_msg}")
        
    # Update status to RESOLVED
    cursor.execute("UPDATE threat_recommendations SET status = 'RESOLVED' WHERE id = ?", (rec_id,))
    conn.commit()
    conn.close()
    
    log_event("INFO", f"Threat Engine remedy applied successfully: {row['title']}")
    return {"message": f"Recommendation {rec_id} applied successfully.", "status": "RESOLVED"}

@router.post("/recommendations/resolve-all")
def resolve_all_recommendations():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE threat_recommendations SET status = 'RESOLVED' WHERE status = 'PENDING'")
    conn.commit()
    conn.close()
    log_event("INFO", "All pending threat recommendations resolved in bulk")
    return {"message": "All pending recommendations resolved successfully."}

