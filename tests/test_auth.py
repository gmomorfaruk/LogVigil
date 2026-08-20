import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

import pytest
from fastapi.testclient import TestClient
from main import app
from auth.router import active_sessions
import db

# Use a separate SQLite DB for automated tests
TEST_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test_logvigil.db'))

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    # Override database path to use the test DB
    monkeypatch.setattr(db, "DB_PATH", TEST_DB_PATH)
    db.init_db()
    yield
    # Clean up test DB after test execution
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass

def test_auth_flow():
    with TestClient(app) as client:
        # 1. Register a user
        response = client.post("/api/auth/register", json={"username": "alice", "password": "supersecurepassword"})
        assert response.status_code == 200
        assert response.json()["message"] == "Registration successful"
        
        # 2. Try registering duplicate username
        response = client.post("/api/auth/register", json={"username": "alice", "password": "anotherpassword"})
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
        
        # 3. Try log in with incorrect credentials
        response = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpassword"})
        assert response.status_code == 401
        assert "Invalid username" in response.json()["detail"]
        
        # 4. Log in successfully
        response = client.post("/api/auth/login", json={"username": "alice", "password": "supersecurepassword"})
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Login successful"
        assert "token" in data
        assert data["username"] == "alice"
        token = data["token"]
        
        # 5. Retrieve current session (me)
        response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json()["username"] == "alice"
        assert response.json()["authenticated"] is True
        
        # 6. Log out
        response = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json()["message"] == "Logged out successfully"
        
        # 7. Check session after logging out
        response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
