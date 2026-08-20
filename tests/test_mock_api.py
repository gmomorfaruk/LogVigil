import sys
import os
import pytest
from fastapi.testclient import TestClient

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from main import app
import db
from vault.router import vault_state, active_vault_sessions

# Use a separate SQLite DB for automated tests
TEST_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test_logvigil.db'))

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    # Override database path to use the test DB
    monkeypatch.setattr(db, "DB_PATH", TEST_DB_PATH)
    db.init_db()
    vault_state["locked"] = True
    active_vault_sessions.clear()
    yield
    # Clean up test DB after test execution
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass
    vault_state["locked"] = True
    active_vault_sessions.clear()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_vault_endpoints(client):
    # 1. Register & login user
    client.post("/api/auth/register", json={"username": "tester", "password": "password123"})
    login_res = client.post("/api/auth/login", json={"username": "tester", "password": "password123"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Setup PIN for user
    setup_res = client.post("/api/vault/setup-pin", json={"pin": "1234"}, headers=headers)
    assert setup_res.status_code == 200

    # 3. Check status is initially locked
    res = client.get("/api/vault/status", headers=headers)
    assert res.status_code == 200
    assert res.json()["locked"] is True
    assert res.json()["has_pin"] is True

    # 4. Try fetching files when locked (should be 403 Forbidden)
    res = client.get("/api/vault/files", headers=headers)
    assert res.status_code == 403

    # 5. Toggle vault with wrong PIN (should be 401 Unauthorized)
    res = client.post("/api/vault/toggle", json={"pin": "9999"}, headers=headers)
    assert res.status_code == 401

    # 6. Toggle vault with correct PIN
    res = client.post("/api/vault/toggle", json={"pin": "1234"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["locked"] is False

    # 7. Fetch files now that it's unlocked
    res = client.get("/api/vault/files", headers=headers)
    assert res.status_code == 200
    files = res.json()
    assert len(files) >= 2

    # 8. Encrypt mock file
    res = client.post("/api/vault/encrypt", json={"file_path": "/home/user/documents/secret.txt"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["file_name"] == "secret.txt"

    # 9. Decrypt file
    res = client.post("/api/vault/decrypt", json={"file_id": data["file_id"]}, headers=headers)
    assert res.status_code == 200
    assert res.json()["decrypted_path"] == "/home/user/documents/secret.txt"

    # 10. Decrypt non-existent file
    res = client.post("/api/vault/decrypt", json={"file_id": "file_nonexistent"}, headers=headers)
    assert res.status_code == 404

    # 11. Lock vault again
    res = client.post("/api/vault/toggle", json={"pin": "1234"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["locked"] is True


def test_firewall_endpoints(client):
    # 1. Get status
    res = client.get("/api/firewall/status")
    assert res.status_code == 200
    assert res.json()["enabled"] is False

    # 2. Toggle status
    res = client.post("/api/firewall/toggle", json={"enable": True})
    assert res.status_code == 200
    assert res.json()["enabled"] is True

    # 3. Get rules
    res = client.get("/api/firewall/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 2

    # 4. Create firewall rule
    new_rule = {
        "protocol": "TCP",
        "port": 8080,
        "action": "BLOCK",
        "direction": "INBOUND",
        "description": "Block test dev port"
    }
    res = client.post("/api/firewall/rules", json=new_rule)
    assert res.status_code == 201
    rule_data = res.json()
    assert rule_data["port"] == 8080
    assert rule_data["action"] == "BLOCK"
    rule_id = rule_data["id"]

    # 5. Delete created rule
    res = client.delete(f"/api/firewall/rules/{rule_id}")
    assert res.status_code == 200
    assert "deleted successfully" in res.json()["message"]


def test_integrity_endpoints(client):
    # 1. Get status
    res = client.get("/api/integrity/status")
    assert res.status_code == 200
    status = res.json()
    assert "monitored_folders" in status
    assert "protected_files_count" in status

    # 2. Add monitored directory (using backend logs folder as a test dir)
    temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend/logs'))
    os.makedirs(temp_dir, exist_ok=True)
    res = client.post("/api/integrity/monitor", json={"folder_path": temp_dir})
    assert res.status_code in (200, 400)  # 400 if already monitored

    # 3. Run integrity scan
    res = client.post("/api/integrity/scan")
    assert res.status_code == 200
    scan_res = res.json()
    assert "scanned_files" in scan_res

    # 4. Get alerts
    res = client.get("/api/integrity/alerts")
    assert res.status_code == 200


def test_phishing_endpoint(client):
    # Test safe URL
    res = client.post("/api/phishing/analyze", json={"url": "https://google.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW"
    assert data["safety_score"] >= 80.0
    assert data["details"]["https_enabled"] is True

    # Test dangerous typosquatting URL
    res = client.post("/api/phishing/analyze", json={"url": "http://goog1e.com/login"})
    assert res.status_code == 200
    data_bad = res.json()
    assert data_bad["risk_level"] == "HIGH"
    assert data_bad["details"]["typosquatting_detected"] is True
    assert data_bad["details"]["https_enabled"] is False


def test_network_monitor_endpoints(client):
    # 1. Get status
    res = client.get("/api/network/status")
    assert res.status_code == 200
    assert "active" in res.json()

    # 2. Toggle active status
    res = client.post("/api/network/toggle", json={"active": True})
    assert res.status_code == 200
    assert res.json()["active"] is True

    # 3. Get alerts
    res = client.get("/api/network/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    assert alerts[0]["risk_level"] in ["HIGH", "MEDIUM", "LOW"]


def test_threat_engine_endpoints(client):
    # 1. Get summary initially
    res = client.get("/api/alerts/summary")
    assert res.status_code == 200
    summary = res.json()
    assert "overall_risk" in summary
    assert "total_alerts" in summary

    # 2. Get threat recommendations
    res = client.get("/api/alerts/recommendations")
    assert res.status_code == 200
    recs = res.json()
    assert len(recs) >= 1

    # 3. Apply a recommendation
    rec_id = recs[0]["id"]
    res = client.post(f"/api/alerts/recommendations/{rec_id}/apply")
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"


def test_reports_endpoints(client):
    # 1. List reports
    res = client.get("/api/reports/list")
    assert res.status_code == 200
    reports = res.json()
    assert len(reports) >= 1

    # 2. Generate a new report
    res = client.post("/api/reports/generate", json={"report_type": "AUDIT_SUMMARY"})
    assert res.status_code == 201
    new_report = res.json()
    assert new_report["report_type"] == "AUDIT_SUMMARY"
    report_id = new_report["id"]

    # 3. Download the report PDF bytes
    res = client.get(f"/api/reports/download/{report_id}")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-1.4")


def test_timeline_endpoint(client):
    # 1. Fetch timeline
    res = client.get("/api/timeline")
    assert res.status_code == 200
    timeline = res.json()
    assert isinstance(timeline, list)
    if len(timeline) > 0:
        assert "event_type" in timeline[0]
        assert "timestamp" in timeline[0]


def test_settings_endpoints(client):
    # 1. Get settings
    res = client.get("/api/settings")
    assert res.status_code == 200
    settings = res.json()
    assert "dark_mode" in settings

    # 2. Update settings
    updated_settings = {
        "dark_mode": True,
        "notifications_enabled": False,
        "auto_update": True,
        "backup_frequency": "DAILY"
    }
    res = client.post("/api/settings", json=updated_settings)
    assert res.status_code == 200
    assert res.json()["notifications_enabled"] is False
    assert res.json()["backup_frequency"] == "DAILY"


def test_security_score_endpoint(client):
    res = client.get("/api/security-score")
    assert res.status_code == 200
    score = res.json()
    assert "overall_score" in score
    assert "breakdown" in score
    assert 0 <= score["overall_score"] <= 100


def test_logging_system(client):
    res = client.post("/api/firewall/toggle", json={"enable": True})
    assert res.status_code == 200

    res = client.get("/api/logs")
    assert res.status_code == 200
    logs = res.json()
    assert len(logs) >= 1
    assert any("Firewall toggled" in log["message"] for log in logs)


def test_real_file_cryptography(client):
    # 1. Register & login user
    client.post("/api/auth/register", json={"username": "crypto_user", "password": "password123"})
    login_res = client.post("/api/auth/login", json={"username": "crypto_user", "password": "password123"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/vault/setup-pin", json={"pin": "1234"}, headers=headers)

    # 2. Create temporary test file
    temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend/logs'))
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, "vault_test_real.txt")
    plaintext = b"This is some highly confidential real plaintext data to test AES-256-GCM streaming."
    with open(temp_file, "wb") as f:
        f.write(plaintext)

    # 3. Unlock vault
    res = client.post("/api/vault/toggle", json={"pin": "1234"}, headers=headers)
    assert res.status_code == 200

    # 3.5 Test path validation errors
    # Test non-existent path
    non_existent = os.path.join(temp_dir, "this_does_not_exist_xyz.txt")
    res_non_existent = client.post("/api/vault/encrypt", json={"file_path": non_existent}, headers=headers)
    assert res_non_existent.status_code == 404
    assert "does not exist" in res_non_existent.json()["detail"]

    # Test directory path
    res_directory = client.post("/api/vault/encrypt", json={"file_path": temp_dir}, headers=headers)
    assert res_directory.status_code == 400
    assert "directory" in res_directory.json()["detail"]

    # 4. Encrypt file
    res = client.post("/api/vault/encrypt", json={"file_path": temp_file}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    encrypted_path = data["encrypted_path"]
    file_id = data["file_id"]

    assert not os.path.exists(temp_file)
    assert os.path.exists(encrypted_path)

    # 5. Decrypt file
    res = client.post("/api/vault/decrypt", json={"file_id": file_id}, headers=headers)
    assert res.status_code == 200

    assert os.path.exists(temp_file)
    assert not os.path.exists(encrypted_path)

    with open(temp_file, "rb") as f:
        restored_plaintext = f.read()
    assert restored_plaintext == plaintext

    if os.path.exists(temp_file):
        os.remove(temp_file)


def test_password_vault_endpoints(client):
    # 1. Register & login user
    client.post("/api/auth/register", json={"username": "pwd_user", "password": "password123"})
    login_res = client.post("/api/auth/login", json={"username": "pwd_user", "password": "password123"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/vault/setup-pin", json={"pin": "1234"}, headers=headers)

    # Unlock vault
    res = client.post("/api/vault/toggle", json={"pin": "1234"}, headers=headers)
    assert res.status_code == 200

    # Add password
    new_cred = {
        "website": "github.com",
        "username": "gituser",
        "password": "mygitpassword1"
    }
    res = client.post("/api/vault/passwords", json=new_cred, headers=headers)
    assert res.status_code == 201
    cred_id = res.json()["id"]

    # Delete password
    res = client.delete(f"/api/vault/passwords/{cred_id}", headers=headers)
    assert res.status_code == 200


def test_master_key_unlock_and_decrypt(client):
    # 1. Register & login user
    client.post("/api/auth/register", json={"username": "master_user", "password": "password123"})
    login_res = client.post("/api/auth/login", json={"username": "master_user", "password": "password123"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Setup PIN + Master Key
    res = client.post("/api/vault/setup-pin", json={"pin": "1234", "master_key": "backupkey123"}, headers=headers)
    assert res.status_code == 200

    # 3. Unlock with PIN
    res = client.post("/api/vault/toggle", json={"pin": "1234"}, headers=headers)
    assert res.status_code == 200

    # 4. Add password
    new_cred = {
        "website": "target.com",
        "username": "targetuser",
        "password": "mytargetpass"
    }
    res = client.post("/api/vault/passwords", json=new_cred, headers=headers)
    assert res.status_code == 201
    cred_id = res.json()["id"]

    # 5. Lock vault
    res = client.post("/api/vault/toggle", json={}, headers=headers)
    assert res.status_code == 200
    assert res.json()["locked"] is True

    # 6. Trigger Stage 2 by entering wrong PIN
    res = client.post("/api/vault/toggle", json={"pin": "wrongpin"}, headers=headers)
    assert res.status_code == 401

    # Check status stage
    status_res = client.get("/api/vault/status", headers=headers)
    assert status_res.json()["unlock_stage"] == "master_key"

    # 7. Unlock with Master Key
    res = client.post("/api/vault/toggle", json={"master_key": "backupkey123"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["locked"] is False

    # 8. Retrieve passwords and verify correct decryption (no mismatch / [DECRYPTION_ERROR])
    res = client.get("/api/vault/passwords", headers=headers)
    assert res.status_code == 200
    creds = res.json()
    my_cred = next((c for c in creds if c["id"] == cred_id), None)
    assert my_cred is not None
    assert my_cred["password"] == "mytargetpass"

    # Cleanup
    client.delete(f"/api/vault/passwords/{cred_id}", headers=headers)


def test_integrity_deleted_alert_deduplication(client):
    import shutil
    # 1. Create a monitored temp directory
    temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend/logs/integrity_test_dedup'))
    os.makedirs(temp_dir, exist_ok=True)

    # 2. Add monitored directory
    client.post("/api/integrity/monitor", json={"folder_path": temp_dir})

    # 3. Create a temporary file and baseline it
    temp_file = os.path.join(temp_dir, "test_file_to_delete.txt")
    with open(temp_file, "w") as f:
        f.write("Integrity test content.")

    # Re-add directory to force baseline calculation for this newly added file
    client.request("DELETE", "/api/integrity/monitor", json={"folder_path": temp_dir})
    client.post("/api/integrity/monitor", json={"folder_path": temp_dir})

    # Verify file is baselined
    res = client.get("/api/integrity/status")
    assert res.json()["protected_files_count"] >= 1

    # Clear prior alerts first
    client.request("DELETE", "/api/integrity/alerts")

    # 5. Delete the file
    if os.path.exists(temp_file):
        os.remove(temp_file)

    # 6. Run scan 1
    res1 = client.post("/api/integrity/scan")
    assert res1.status_code == 200
    assert res1.json()["new_alerts"] == 1

    # Verify alert created
    res_alerts = client.get("/api/integrity/alerts")
    alerts1 = res_alerts.json()
    deleted_alerts = [a for a in alerts1 if a["file_path"] == temp_file and a["alert_type"] == "DELETED"]
    assert len(deleted_alerts) == 1

    # 7. Run scan 2 (should NOT trigger a duplicate alert since baseline was deleted)
    res2 = client.post("/api/integrity/scan")
    assert res2.status_code == 200
    assert res2.json()["new_alerts"] == 0

    res_alerts2 = client.get("/api/integrity/alerts")
    alerts2 = res_alerts2.json()
    deleted_alerts2 = [a for a in alerts2 if a["file_path"] == temp_file and a["alert_type"] == "DELETED"]
    assert len(deleted_alerts2) == 1  # Still exactly 1 alert total from first scan

    # Cleanup
    client.request("DELETE", "/api/integrity/monitor", json={"folder_path": temp_dir})
    client.request("DELETE", "/api/integrity/alerts")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


def test_backup_restore_endpoints(client):
    # 1. Trigger backup
    res = client.post("/api/settings/backup")
    assert res.status_code == 200
    assert "backup created successfully" in res.json()["message"].lower()

    # 2. Trigger restore
    res = client.post("/api/settings/restore")
    assert res.status_code == 200
    assert "restored successfully" in res.json()["message"].lower()
