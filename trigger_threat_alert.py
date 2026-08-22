#!/usr/bin/env python3
"""
trigger_threat_alert.py
────────────────────────
Injects a simulated threat recommendation into LogVigil's database.
This makes a yellow dot / alert appear on the Threats & Recommendations page.

Usage:
  python3 trigger_threat_alert.py
  python3 trigger_threat_alert.py --type MALWARE
  python3 trigger_threat_alert.py --type SQL_INJECTION
  python3 trigger_threat_alert.py --type PORT_SCAN
  python3 trigger_threat_alert.py --type BRUTE_FORCE

Make sure the backend is running before refreshing the Threats page.
"""

import sqlite3
import sys

DB_PATH = '/home/gm/Videos/CryptGuard/database/logvigil.db'

TEMPLATES = {
    "SQL_INJECTION": {
        "title":       "Enable Inbound Port Block",
        "description": "Simulated SQL Injection detected on port 3306 — block inbound MySQL traffic",
        "action_type": "FIREWALL_ENABLE",
    },
    "MALWARE": {
        "title":       "Kill Suspicious Process",
        "description": "Simulated Malware C2 beacon detected — terminate process and block outbound IP",
        "action_type": "PROCESS_KILL",
    },
    "PORT_SCAN": {
        "title":       "Block Port Scanner IP",
        "description": "Simulated port scan from 192.168.1.100 — firewall block recommended",
        "action_type": "FIREWALL_BLOCK",
    },
    "BRUTE_FORCE": {
        "title":       "Block SSH Brute Force",
        "description": "Simulated SSH brute-force attack detected — block source IP on port 22",
        "action_type": "FIREWALL_BLOCK",
    },
}

def inject(threat_type="SQL_INJECTION"):
    tpl = TEMPLATES.get(threat_type.upper(), TEMPLATES["SQL_INJECTION"])

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threat_recommendations")
    count = cursor.fetchone()[0]

    rec_id    = f"rec_{count+1:03d}"
    threat_id = f"simulated_{threat_type.lower()}_{count+1}"

    cursor.execute(
        "INSERT INTO threat_recommendations "
        "(id, threat_id, title, description, action_type, action_payload, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rec_id, threat_id, tpl["title"],
         f"{tpl['description']} (alert #{count+1})",
         tpl["action_type"], '{}', 'PENDING')
    )
    conn.commit()
    conn.close()

    print(f"\n✅ Threat Alert injected!")
    print(f"   Type   : {threat_type.upper()}")
    print(f"   ID     : {rec_id}")
    print(f"   Title  : {tpl['title']}")
    print(f"   Action : {tpl['action_type']}")
    print(f"\n→ Go to Threats & Recommendations page and refresh to see the alert.\n")

if __name__ == "__main__":
    threat_type = "SQL_INJECTION"
    for arg in sys.argv[1:]:
        if arg.startswith("--type"):
            parts = arg.split("=")
            if len(parts) == 2:
                threat_type = parts[1]
            elif len(sys.argv) > sys.argv.index(arg) + 1:
                threat_type = sys.argv[sys.argv.index(arg) + 1]

    inject(threat_type)
