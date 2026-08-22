import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database")
DB_PATH = os.path.join(DB_DIR, "logvigil.db")

def get_db():
    """
    Returns a SQLite database connection with row factory configured to dict-like access.
    Automatically ensures the database directory exists.
    """
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database schema if it doesn't already exist.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        operator TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS encrypted_files (
        file_id TEXT PRIMARY KEY,
        file_name TEXT NOT NULL,
        original_path TEXT NOT NULL,
        encrypted_path TEXT NOT NULL,
        encrypted_at TEXT NOT NULL,
        size INTEGER NOT NULL
    )
    """)
    
    # Seed initial mock files if table is empty
    cursor.execute("SELECT COUNT(*) as count FROM encrypted_files")
    row = cursor.fetchone()
    count = row["count"] if row else 0
    if count == 0:
        cursor.executemany(
            "INSERT INTO encrypted_files (file_id, file_name, original_path, encrypted_path, encrypted_at, size) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("file_001", "tax_returns_2025.pdf", "/home/user/documents/tax_returns_2025.pdf", "/home/user/documents/tax_returns_2025.pdf.enc", "2026-08-08T04:12:00Z", 1048576),
                ("file_002", "master_keys.txt", "/home/user/desktop/master_keys.txt", "/home/user/desktop/master_keys.txt.enc", "2026-08-08T05:22:30Z", 512)
            ]
        )
        
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        encrypted_password TEXT NOT NULL
    )
    """)
    
    # Seed initial mock passwords if table is empty
    cursor.execute("SELECT COUNT(*) as count FROM password_vault")
    pwd_count = cursor.fetchone()["count"]
    if pwd_count == 0:
        cursor.execute(
            "INSERT INTO password_vault (website, username, encrypted_password) VALUES (?, ?, ?)",
            ("google.com", "operator", "930f47f6f9fb5874b21f1459a5bd6efd30156a8d2075b0b9d75dd3449e6dc243855202befe66449e7874")
        )
        
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id TEXT PRIMARY KEY,
        protocol TEXT NOT NULL,
        port INTEGER NOT NULL,
        action TEXT NOT NULL,
        direction TEXT NOT NULL,
        description TEXT,
        ip_address TEXT
    )
    """)
    try:
        cursor.execute("ALTER TABLE firewall_rules ADD COLUMN ip_address TEXT")
        conn.commit()
    except Exception:
        pass
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_status (
        enabled INTEGER NOT NULL DEFAULT 0
    )
    """)
    
    # Seed default status if empty
    cursor.execute("SELECT COUNT(*) as count FROM firewall_status")
    if cursor.fetchone()["count"] == 0:
        cursor.execute("INSERT INTO firewall_status (enabled) VALUES (0)")
        
    # Seed default rules if empty
    cursor.execute("SELECT COUNT(*) as count FROM firewall_rules")
    if cursor.fetchone()["count"] == 0:
        cursor.executemany(
            "INSERT INTO firewall_rules (id, protocol, port, action, direction, description) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("rule_001", "TCP", 80, "ALLOW", "INBOUND", "HTTP traffic"),
                ("rule_002", "TCP", 22, "BLOCK", "INBOUND", "SSH remote access")
            ]
        )
        
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_baselines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_path TEXT NOT NULL,
        file_path TEXT NOT NULL UNIQUE,
        sha256_hash TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        baselined_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS integrity_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        hash_old TEXT,
        hash_new TEXT,
        detected_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_recommendations (
        id TEXT PRIMARY KEY,
        threat_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        action_type TEXT NOT NULL,
        action_payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING'
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_pins (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        pin_hash TEXT NOT NULL,
        pin_salt TEXT NOT NULL,
        vault_salt TEXT NOT NULL,
        master_key_hash TEXT,
        encrypted_key_by_pin TEXT,
        encrypted_key_by_master TEXT
    )
    """)
    # Safe migration: add columns if they don't exist yet
    try:
        cursor.execute("ALTER TABLE vault_pins ADD COLUMN master_key_hash TEXT")
        conn.commit()
    except Exception:
        pass  # Column already exists — idempotent
    try:
        cursor.execute("ALTER TABLE vault_pins ADD COLUMN encrypted_key_by_pin TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE vault_pins ADD COLUMN encrypted_key_by_master TEXT")
        conn.commit()
    except Exception:
        pass
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )
    """)
    # ---------------------------------------------------------------------------
    # Security: Vault DB-backed sessions (replaces in-memory dict)
    # ---------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_sessions (
        session_id   TEXT PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users(id),
        unlocked_at  TEXT NOT NULL,
        last_activity TEXT NOT NULL,
        expires_at   TEXT NOT NULL
    )
    """)
    # ---------------------------------------------------------------------------
    # Security: Vault brute-force protection state
    # ---------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_security (
        user_id         INTEGER PRIMARY KEY REFERENCES users(id),
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        lockout_until   TEXT,
        last_failed_at  TEXT
    )
    """)
    # ---------------------------------------------------------------------------
    # Security: Login brute-force tracking (per-username + per-IP)
    # ---------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT NOT NULL,
        ip_address   TEXT NOT NULL,
        failed_count INTEGER NOT NULL DEFAULT 0,
        lockout_until TEXT,
        last_attempt TEXT NOT NULL,
        UNIQUE(username, ip_address)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)
    # Seed default system settings if empty
    cursor.execute("SELECT COUNT(*) as count FROM system_settings")
    if cursor.fetchone()["count"] == 0:
        cursor.executemany(
            "INSERT INTO system_settings (key, value) VALUES (?, ?)",
            [
                ("dark_mode", "true"),
                ("notifications_enabled", "true"),
                ("auto_update", "false"),
                ("backup_frequency", "WEEKLY"),
                ("last_backup_time", ""),
                ("activity_monitor_enabled", "false"),
                ("activity_poll_interval", "5")
            ]
        )
    else:
        # Ensure activity monitor settings exist for existing databases
        for key, default_val in [("activity_monitor_enabled", "false"), ("activity_poll_interval", "5")]:
            cursor.execute(
                "INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING",
                (key, default_val)
            )
    # ---------------------------------------------------------------------------
    # Phase 15: Local Activity Monitor — process/app tracking
    # ---------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT    NOT NULL,
        event_type TEXT   NOT NULL,
        target    TEXT    NOT NULL,
        details   TEXT,
        pid       INTEGER,
        username  TEXT
    )
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_logs(timestamp)
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_activity_event_type ON activity_logs(event_type)
    """)
    conn.commit()
    conn.close()


def migrate_db():
    """
    Safe schema migrations — adds new columns/tables without breaking existing data.
    Called after init_db() on every startup.
    """
    conn = get_db()
    cursor = conn.cursor()

    # ---------------------------------------------------------------------------
    # Lock 3: RSA key pairs per user
    # ---------------------------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fim_keypairs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        username         TEXT NOT NULL UNIQUE,
        public_key       TEXT NOT NULL,
        private_key_enc  TEXT NOT NULL,
        private_key_salt TEXT NOT NULL,
        created_at       TEXT NOT NULL
    )
    """)

    # ---------------------------------------------------------------------------
    # Lock 3 columns on integrity_baselines
    # ---------------------------------------------------------------------------
    for col_def in [
        ("lock3_enabled",  "INTEGER DEFAULT 0"),
        ("lock3_path",     "TEXT"),
        ("lock3_hash",     "TEXT"),   # SHA-256 of plaintext at time of locking
    ]:
        try:
            cursor.execute(f"ALTER TABLE integrity_baselines ADD COLUMN {col_def[0]} {col_def[1]}")
        except Exception:
            pass  # Column already exists — idempotent

    conn.commit()
    conn.close()

