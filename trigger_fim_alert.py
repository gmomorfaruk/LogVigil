#!/usr/bin/env python3
"""
trigger_fim_alert.py
────────────────────
Demo script to generate a live RED ALERT in LogVigil's FIM monitor.

Steps it does automatically:
  1. Creates a temp test file with known content
  2. Registers its folder with the FIM monitor (POST /api/integrity/monitor)
  3. Waits 1 second
  4. MODIFIES the file content (simulates an attacker editing the file)
  5. Triggers a scan (POST /api/integrity/scan)
  6. Prints the result — you'll see a red MODIFIED alert in the UI

Usage:
  python3 trigger_fim_alert.py

Make sure the backend is running on localhost:8000 before running this.
"""

import os
import time
import json
import urllib.request
import urllib.error
import tempfile

BASE = "http://localhost:8000"
TEST_DIR = os.path.join(tempfile.gettempdir(), "logvigil_demo")
TEST_FILE = os.path.join(TEST_DIR, "sensitive_config.txt")


def api(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return json.loads(res.read()), res.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def banner(text, char="─"):
    print(f"\n{char * 55}")
    print(f"  {text}")
    print(f"{char * 55}")


def main():
    banner("LogVigil FIM Red Alert Demo", "═")

    # ── Step 1: Create test directory and file ───────────────────────────
    os.makedirs(TEST_DIR, exist_ok=True)
    with open(TEST_FILE, "w") as f:
        f.write("SYSTEM CONFIG — DO NOT MODIFY\n")
        f.write("db_password=super_secret_123\n")
        f.write("api_key=logvigil-prod-key-xyz\n")

    print(f"\n[1] ✅ Test file created:")
    print(f"    {TEST_FILE}")

    # ── Step 2: Register the folder with FIM ────────────────────────────
    print(f"\n[2] 📡 Registering folder with FIM monitor...")
    resp, status = api("POST", "/api/integrity/monitor", {"folder_path": TEST_DIR})

    if status == 400 and "already monitored" in str(resp):
        print(f"    ℹ  Folder already monitored — baseline already exists.")
    elif status == 200:
        print(f"    ✅ {resp.get('message', 'OK')}")
    else:
        print(f"    ⚠  Status {status}: {resp}")

    # ── Step 3: Small delay so baseline is committed ─────────────────────
    print(f"\n[3] ⏱  Waiting 1 second...")
    time.sleep(1)

    # ── Step 4: TAMPER the file ──────────────────────────────────────────
    with open(TEST_FILE, "a") as f:
        f.write("\n# INJECTED BY ATTACKER — backdoor=true\n")
        f.write("root_access=enabled\n")

    print(f"\n[4] 🔴 File TAMPERED — malicious content injected:")
    print(f"    {TEST_FILE}")

    # ── Step 5: Trigger scan ─────────────────────────────────────────────
    print(f"\n[5] 🔍 Running integrity scan...")
    resp, status = api("POST", "/api/integrity/scan")

    if status == 200:
        scanned = resp.get("scanned_files", 0)
        alerts  = resp.get("new_alerts", 0)
        print(f"    ✅ Scan complete: {scanned} files checked, {alerts} new alert(s)")
    else:
        print(f"    ⚠  Scan error: {resp}")

    # ── Step 6: Show current alerts ──────────────────────────────────────
    resp, status = api("GET", "/api/integrity/alerts")
    if status == 200 and resp:
        banner("🚨 ACTIVE INTEGRITY ALERTS", "!")
        for alert in resp[:5]:  # show latest 5
            atype = alert.get("alert_type", "?")
            fpath = alert.get("file_path", "?")
            ts    = alert.get("detected_at", "?")
            print(f"  [{atype}] {fpath}")
            print(f"           at {ts}")
            if alert.get("hash_old"):
                print(f"           baseline : {alert['hash_old'][:32]}...")
            if alert.get("hash_new"):
                print(f"           current  : {alert['hash_new'][:32]}...")
            print()
    else:
        print("\n  No alerts returned. Check the dashboard.")

    banner("Done — Check the LogVigil FIM page in your browser!", "═")
    print("  → Go to: File Integrity → MODIFICATION ALERTS FEED")
    print("  → You should see a red MODIFIED badge for:")
    print(f"    {TEST_FILE}\n")


if __name__ == "__main__":
    main()
