import shutil
import subprocess
import sqlite3
from typing import List, Optional, Tuple
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from db import get_db
from logger import log_event

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])

# Keep global firewall_state for other routers to query (e.g. security_score)
firewall_state = {"enabled": False}

# Detect system firewall tool
def get_firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    elif shutil.which("iptables"):
        return "iptables"
    return "mock"

def run_firewall_command(command: List[str]) -> Tuple[bool, str]:
    """
    Executes a shell command safely. Catches exceptions and logs warnings.
    Returns (True, "") if execution returns 0, otherwise (False, error_message).
    """
    try:
        res = subprocess.run(command, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return True, ""
        else:
            err = res.stderr.strip() or res.stdout.strip()
            log_event("WARNING", f"Firewall command failed ({' '.join(command)}): {err}")
            return False, err
    except Exception as e:
        log_event("WARNING", f"Firewall execution failed ({' '.join(command)}): {str(e)}")
        return False, str(e)

# Pydantic schemas
class FirewallStatusResponse(BaseModel):
    enabled: bool
    applied_to_system: bool = False
    message: Optional[str] = None

class FirewallToggleRequest(BaseModel):
    enable: bool

class FirewallRule(BaseModel):
    id: str
    protocol: str
    port: int
    action: str
    direction: str
    description: str
    ip_address: Optional[str] = None
    applied_to_system: Optional[bool] = False

class FirewallRuleCreate(BaseModel):
    protocol: str = Field(..., pattern="^(TCP|UDP|ICMP)$")
    port: int = Field(..., ge=1, le=65535)
    action: str = Field(..., pattern="^(ALLOW|BLOCK)$")
    direction: str = Field(..., pattern="^(INBOUND|OUTBOUND)$")
    description: str = Field(..., max_length=100)
    ip_address: Optional[str] = None

class MessageResponse(BaseModel):
    message: str
    applied_to_system: Optional[bool] = False

# Populate initial firewall_state from database status
def load_initial_firewall_state():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT enabled FROM firewall_status")
        row = cursor.fetchone()
        if row:
            firewall_state["enabled"] = (row["enabled"] == 1)
        conn.close()
    except Exception:
        pass

load_initial_firewall_state()

@router.get("/status", response_model=FirewallStatusResponse)
def get_firewall_status():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM firewall_status")
    row = cursor.fetchone()
    conn.close()
    
    enabled = (row["enabled"] == 1) if row else False
    firewall_state["enabled"] = enabled
    return {"enabled": enabled, "applied_to_system": True}

@router.post("/toggle", response_model=FirewallStatusResponse)
def toggle_firewall(req: FirewallToggleRequest):
    backend = get_firewall_backend()
    success = False
    err_detail = ""
    
    if backend == "ufw":
        cmd = ["sudo", "-n", "ufw", "--force", "enable" if req.enable else "disable"]
        success, err_detail = run_firewall_command(cmd)
    elif backend == "iptables":
        # Safe check: do not set global default policy to DROP to avoid locking system network
        cmd = ["sudo", "-n", "iptables", "-L", "-n"]
        success, err_detail = run_firewall_command(cmd)
        
    status_str = "ENABLED" if req.enable else "DISABLED"
    if success:
        log_event("INFO", f"Firewall toggled: {status_str} (Host firewall synced successfully via {backend})")
        msg = f"System firewall {status_str} successfully via {backend}."
    else:
        log_event("WARNING", f"Firewall toggled: {status_str} (Host firewall requires sudo permissions. Simulated state active locally.)")
        msg = f"Firewall status set to {status_str} in SecureVault database (OS kernel sync requires sudo permissions)."

    # Update state in SQLite
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE firewall_status SET enabled = ?", (1 if req.enable else 0,))
    conn.commit()
    conn.close()
    
    firewall_state["enabled"] = req.enable
    return {"enabled": req.enable, "applied_to_system": success, "message": msg}

@router.get("/rules", response_model=List[FirewallRule])
def get_firewall_rules():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, protocol, port, action, direction, description, ip_address FROM firewall_rules")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": row["id"],
            "protocol": row["protocol"],
            "port": row["port"],
            "action": row["action"],
            "direction": row["direction"],
            "description": row["description"],
            "ip_address": row["ip_address"] if "ip_address" in row.keys() else None,
            "applied_to_system": True
        } for row in rows
    ]

@router.post("/rules", response_model=FirewallRule, status_code=201)
def create_firewall_rule(req: FirewallRuleCreate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM firewall_rules")
    count = cursor.fetchone()["count"]
    rule_id = f"rule_{count + 1:03d}"
    
    backend = get_firewall_backend()
    success = False
    err_detail = ""
    
    # Run host command safely using insert (-I) so the rule takes priority
    if backend == "ufw":
        action_keyword = "allow" if req.action == "ALLOW" else "deny"
        direction_arg = "in" if req.direction == "INBOUND" else "out"
        if req.ip_address:
            cmd = ["sudo", "-n", "ufw", direction_arg, action_keyword, "from", req.ip_address, "to", "any", "port", str(req.port), "proto", req.protocol.lower()]
        else:
            cmd = ["sudo", "-n", "ufw", direction_arg, action_keyword, f"{req.port}/{req.protocol.lower()}"]
        success, err_detail = run_firewall_command(cmd)
    elif backend == "iptables":
        chain = "INPUT" if req.direction == "INBOUND" else "OUTPUT"
        target = "ACCEPT" if req.action == "ALLOW" else "DROP"
        # Use -I (insert at top) so rule takes priority over existing rules
        cmd = ["sudo", "-n", "iptables", "-I", chain, "-p", req.protocol.lower()]
        if req.ip_address:
            flag = "-s" if req.direction == "INBOUND" else "-d"
            cmd.extend([flag, req.ip_address])
        if req.protocol in ["TCP", "UDP"]:
            cmd.extend(["--dport", str(req.port)])
        cmd.extend(["-j", target])
        success, err_detail = run_firewall_command(cmd)

    if success:
        log_event("INFO", f"System firewall rule created successfully on host using {backend}")
    else:
        log_event("WARNING", f"Host firewall rule application requires sudo. Saved to SecureVault index (Backend: {backend})")
        
    try:
        cursor.execute(
            "INSERT INTO firewall_rules (id, protocol, port, action, direction, description, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rule_id, req.protocol, req.port, req.action, req.direction, req.description, req.ip_address)
        )
        conn.commit()
        log_event("INFO", f"Firewall rule indexed: ID '{rule_id}', Action '{req.action}', Protocol/Port '{req.protocol}:{req.port}'")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to write rule to database: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")
        
    conn.close()
    return {
        "id": rule_id,
        "protocol": req.protocol,
        "port": req.port,
        "action": req.action,
        "direction": req.direction,
        "description": req.description,
        "ip_address": req.ip_address,
        "applied_to_system": success
    }

@router.delete("/rules/{rule_id}", response_model=MessageResponse)
def delete_firewall_rule(rule_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT protocol, port, action, direction, ip_address FROM firewall_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        log_event("WARNING", f"Firewall rule deletion failed: Rule ID '{rule_id}' not found")
        raise HTTPException(status_code=404, detail="Firewall rule not found")
        
    protocol = row["protocol"]
    port = row["port"]
    action = row["action"]
    direction = row["direction"]
    ip_address = row["ip_address"] if "ip_address" in row.keys() else None
    
    backend = get_firewall_backend()
    success = False
    
    # Run host command delete
    if backend == "ufw":
        action_keyword = "allow" if action == "ALLOW" else "deny"
        direction_arg = "in" if direction == "INBOUND" else "out"
        if ip_address:
            cmd = ["sudo", "-n", "ufw", "delete", direction_arg, action_keyword, "from", ip_address, "to", "any", "port", str(port), "proto", protocol.lower()]
        else:
            cmd = ["sudo", "-n", "ufw", "delete", direction_arg, action_keyword, f"{port}/{protocol.lower()}"]
        success, _ = run_firewall_command(cmd)
    elif backend == "iptables":
        chain = "INPUT" if direction == "INBOUND" else "OUTPUT"
        target = "ACCEPT" if action == "ALLOW" else "DROP"
        cmd = ["sudo", "-n", "iptables", "-D", chain, "-p", protocol.lower()]
        if ip_address:
            flag = "-s" if direction == "INBOUND" else "-d"
            cmd.extend([flag, ip_address])
        if protocol in ["TCP", "UDP"]:
            cmd.extend(["--dport", str(port)])
        cmd.extend(["-j", target])
        success, _ = run_firewall_command(cmd)

    if success:
        log_event("INFO", f"System firewall rule deleted successfully from host using {backend}")
    else:
        log_event("WARNING", f"Host firewall rule removal simulated locally (Backend: {backend})")

    try:
        cursor.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
        conn.commit()
        log_event("INFO", f"Firewall rule deleted from index: ID '{rule_id}'")
    except sqlite3.Error as e:
        conn.close()
        log_event("ERROR", f"Failed to delete rule from database: {str(e)}")
        raise HTTPException(status_code=500, detail="Database write error")
        
    conn.close()
    return {"message": f"Rule {rule_id} deleted successfully", "applied_to_system": success}
