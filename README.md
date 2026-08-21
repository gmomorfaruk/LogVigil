# 🛡️ LogVigil — Linux Security Monitor & Log Analyzer

> A comprehensive desktop security platform built with **FastAPI**, **React 19**, and **SQLite**.  
> LogVigil provides real-time threat intelligence, file encryption, phishing detection, firewall control,
> network monitoring, file integrity verification, and a full audit timeline — all in a unified cyber-themed UI.

---

## ✨ Feature Modules

| Module | Description |
|:---|:---|
| **Authentication** | Secure login/register with PBKDF2-HMAC-SHA256 (100 000 iterations). Brute-force lockout after 5 failed attempts (15-minute IP+username block). DB-persisted sessions with 24-hour auto-expiry. |
| **Encrypted Vault** | AES-256-GCM file encryption/decryption with per-user PBKDF2-derived keys. PIN-protected unlock with progressive lockout (30 min → 2 h → 24 h). Optional master key recovery. DB-backed sessions with 5-minute inactivity timeout. |
| **Password Vault** | Encrypted credential storage (website, username, password) using AES-256-GCM. Passwords decryptable only within an active vault session. |
| **File Integrity Monitor** | Real SHA-256 baseline hashing of entire folders. Change detection on re-scan (MODIFIED / ADDED / DELETED alerts). Chunk-based processing for large files. |
| **Firewall Manager** | SQLite-backed firewall rule management (protocol, port, action, direction, IP). Toggle firewall ON/OFF. All rule changes are audit-logged. |
| **Network Monitor** | Suricata IDS integration via `eve.json` parsing. Real-time alert feed with severity classification (HIGH / MEDIUM / LOW). |
| **Threat Engine** | Automated alert triage: classifies Suricata events, assigns risk levels, and generates recommended countermeasures (block IP, terminate process, isolate host). |
| **Phishing Protection** | Multi-vector URL analysis: HTTPS check, domain blacklist, typosquatting detection (`goog1e`, `paypa1`, `faceb00k`), raw-IP URL detection, credential-injection / URL-spoofing (`@` in authority), and suspicious keyword scan. Returns a 0–100 safety score with `LOW / MEDIUM / HIGH` risk rating. |
| **Security Score** | Composite weighted score aggregated across all modules. Live dashboard widget. |
| **System Timeline** | Chronological event feed aggregating all audit log entries from the database. |
| **Reports** | PDF report generation summarising system security posture, firewall status, integrity alerts, and recommendations. |
| **Settings** | System preferences (dark mode, notifications, auto-update), automated database backup/restore with configurable frequency (DAILY / WEEKLY / MONTHLY), last-backup timestamp tracking. |

---

## 🛠️ Technology Stack

| Layer | Technology |
|:---|:---|
| **Backend** | Python 3.10+ · FastAPI · Uvicorn |
| **Frontend** | React 19 · Vite 8 · Vanilla CSS |
| **Database** | SQLite 3 (single-file, no server required) |
| **Cryptography** | `cryptography` library — AES-256-GCM, PBKDF2-HMAC-SHA256 |
| **Password Hashing** | `argon2-cffi` — Argon2id (time_cost=3, memory=64 MB, parallelism=2) |
| **Network IDS** | Suricata (`eve.json` log parser) |
| **System Integration** | `ufw` / `iptables`, `systemctl` |

---

## 📁 Project Structure

```
CryptGuard/
├── backend/
│   ├── auth/                  # Authentication router (login, register, logout)
│   ├── vault/                 # File encryption, password vault, PIN/master-key management
│   ├── firewall/              # Firewall rule CRUD + toggle
│   ├── integrity/             # SHA-256 baseline scan & change detection
│   ├── network/               # Suricata eve.json parser & alert feed
│   ├── phishing/              # URL phishing analysis engine
│   ├── alerts/                # Threat engine & countermeasure recommendations
│   ├── reports/               # PDF report generation
│   ├── security_score/        # Composite security score calculator
│   ├── timeline/              # Event timeline aggregation
│   ├── settings/              # App settings + automated backup scheduler
│   ├── main.py                # FastAPI application entry point
│   ├── db.py                  # SQLite schema definitions & connection helper
│   ├── logger.py              # Dual-sink audit logger (file + DB)
│   ├── security_service.py    # Argon2id hashing, vault sessions, brute-force protection
│   ├── auth_service.py        # PBKDF2 password hashing utilities
│   └── requirements.txt       # Python dependencies
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Overview.jsx   # System Overview dashboard
│       │   ├── Vault.jsx      # Encrypted Vault + Password Vault UI
│       │   ├── Firewall.jsx   # Firewall rules manager
│       │   ├── Integrity.jsx  # File integrity monitor
│       │   ├── Network.jsx    # Network / Suricata monitor
│       │   ├── Threats.jsx    # Threat engine dashboard
│       │   ├── Phishing.jsx   # URL Phishing & Squatting Inspector
│       │   ├── Timeline.jsx   # System event timeline
│       │   ├── Reports.jsx    # PDF report generator
│       │   └── Settings.jsx   # System settings & backup
│       ├── components/        # Sidebar navigation component
│       ├── App.jsx            # Root app with auth guard & page routing
│       └── App.css            # Cyber-themed dark UI stylesheet
├── database/
│   └── logvigil.db            # SQLite database (auto-created on first run)
├── tests/
│   ├── test_auth.py           # Authentication unit tests
│   ├── test_mock_api.py       # Full API endpoint tests (mocked)
│   └── benchmark.py           # Performance benchmarks
└── docs/
    ├── architecture.md        # System diagrams & database ERD
    ├── api_reference.md       # Complete REST API documentation
    └── threat_model.md        # Security analysis & threat matrix
```

---

## 🗄️ Database Schema

### `users`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `username` | TEXT UNIQUE | Operator login name |
| `password_hash` | TEXT | PBKDF2-HMAC-SHA256 hash |
| `salt` | TEXT | Unique per-user random salt |

### `sessions`
| Column | Type | Notes |
|:---|:---|:---|
| `token` | TEXT PK | Random 64-char hex token |
| `username` | TEXT | Linked operator |
| `created_at` | TEXT | ISO-8601 timestamp |
| `expires_at` | TEXT | 24-hour auto-expiry |

### `vault_pins`
| Column | Type | Notes |
|:---|:---|:---|
| `user_id` | INTEGER PK | References `users.id` |
| `pin_hash` | TEXT | PBKDF2 hash of the PIN |
| `pin_salt` | TEXT | Unique PIN salt |
| `vault_salt` | TEXT | PBKDF2 salt for AES key derivation |
| `master_key_hash` | TEXT | Argon2id hash of optional master key |
| `encrypted_key_by_pin` | TEXT | AES key encrypted with PIN-derived key |
| `encrypted_key_by_master` | TEXT | AES key encrypted with master-key-derived key |

### `vault_sessions`
| Column | Type | Notes |
|:---|:---|:---|
| `session_id` | TEXT PK | Random 64-char hex |
| `user_id` | INTEGER | References `users.id` |
| `unlocked_at` | TEXT | When vault was unlocked |
| `last_activity` | TEXT | Refreshed on every vault API call |
| `expires_at` | TEXT | 5-minute inactivity timeout |

### `vault_security`
| Column | Type | Notes |
|:---|:---|:---|
| `user_id` | INTEGER PK | References `users.id` |
| `failed_attempts` | INTEGER | Count of bad PIN/master-key attempts |
| `lockout_until` | TEXT | ISO-8601 timestamp of lockout expiry |
| `last_failed_at` | TEXT | Timestamp of most recent failure |

### `login_attempts`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `username` | TEXT | Attempted username |
| `ip_address` | TEXT | Source IP address |
| `failed_count` | INTEGER | Failed attempts for this combo |
| `lockout_until` | TEXT | Lockout expiry (15-minute block at 5 failures) |
| `last_attempt` | TEXT | Timestamp of last attempt |

### `encrypted_files`
| Column | Type | Notes |
|:---|:---|:---|
| `file_id` | TEXT PK | UUID |
| `file_name` | TEXT | Original filename |
| `original_path` | TEXT | Absolute source path |
| `encrypted_path` | TEXT | Absolute `.enc` output path |
| `encrypted_at` | TEXT | Timestamp |
| `size` | INTEGER | File size in bytes |

### `password_vault`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `website` | TEXT | Credential site |
| `username` | TEXT | Account username |
| `encrypted_password` | TEXT | AES-256-GCM encrypted, hex-encoded |

### `firewall_rules`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | TEXT PK | Rule UUID |
| `protocol` | TEXT | TCP / UDP |
| `port` | INTEGER | Target port |
| `action` | TEXT | ALLOW / BLOCK |
| `direction` | TEXT | INBOUND / OUTBOUND |
| `description` | TEXT | Human-readable label |
| `ip_address` | TEXT | Optional source/dest IP filter |

### `integrity_baselines`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `folder_path` | TEXT | Monitored directory |
| `file_path` | TEXT UNIQUE | Absolute file path |
| `sha256_hash` | TEXT | Baseline SHA-256 checksum |
| `file_size` | INTEGER | Bytes at baseline time |
| `baselined_at` | TEXT | Timestamp |

### `integrity_alerts`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `file_path` | TEXT | File that changed |
| `alert_type` | TEXT | MODIFIED / ADDED / DELETED |
| `hash_old` | TEXT | Previous hash |
| `hash_new` | TEXT | New hash |
| `detected_at` | TEXT | Timestamp |

### `audit_logs`
| Column | Type | Notes |
|:---|:---|:---|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | TEXT | ISO-8601 |
| `level` | TEXT | INFO / WARNING / ERROR / CRITICAL |
| `message` | TEXT | Event description |
| `operator` | TEXT | Username (if applicable) |

### `system_settings`
| Column | Type | Notes |
|:---|:---|:---|
| `key` | TEXT PK | Setting name |
| `value` | TEXT | Setting value |

---

## 🔐 Security Architecture

### Authentication Flow
```
Register:  Password → Random Salt → PBKDF2-HMAC-SHA256 (100k iter) → Store hash+salt
Login:     Password + stored salt → PBKDF2 → Compare hash → Issue session token (24h)
Lockout:   5 failed attempts (per username+IP) → 15-minute block
```

### Vault Unlock Flow
```
User enters PIN
  → PBKDF2(PIN + pin_salt) → Compare pin_hash
  → If match: derive AES key via PBKDF2(PIN + vault_salt)
  → Create vault_session (DB-persisted, 5-min inactivity TTL)
  → All subsequent vault ops require valid session_id

Failed PIN:
  Attempt 1 → Prompt for master key
  Attempt 2 → 30-minute lockout
  Attempt 3 → 2-hour lockout
  Attempt 4+ → 24-hour lockout (admin recovery required)
```

### Vault Encryption Flow
```
Plaintext file
  → AES-256-GCM encrypt (random nonce per file)
  → nonce (12 bytes) || ciphertext || tag (16 bytes) → .enc file
  → Metadata saved to encrypted_files table
```

### Password Vault Flow
```
Store:    Password → AES-256-GCM encrypt with vault AES key → hex-encoded → DB
Retrieve: hex-encoded ciphertext → AES-256-GCM decrypt (requires active vault session)
```

### Phishing Detection Scoring
```
Base score: 100

Deductions:
  No HTTPS               → -20
  Typosquatting detected → -40   (goog1e, paypa1, faceb00k, etc.)
  Raw IP address domain  → -30   (e.g. http://192.168.1.1/login)
  @ sign in URL (spoof)  → -40   (e.g. https://example.com@192.0.2.10/login)
  Suspicious keywords    → -15   (login, verify, update-account, banking)
  On blacklist           → Score forced to 0

Risk levels:
  80–100 → LOW
  50–79  → MEDIUM
  0–49   → HIGH
```

---

## 🌐 REST API Endpoints

### Auth  `/api/auth`
| Method | Route | Description |
|:---|:---|:---|
| `POST` | `/register` | Create new operator account |
| `POST` | `/login` | Authenticate and receive session token |
| `POST` | `/logout` | Invalidate session |
| `GET` | `/me` | Return current operator info |

### Vault  `/api/vault`
| Method | Route | Description |
|:---|:---|:---|
| `POST` | `/setup-pin` | Set vault PIN and derive AES key |
| `POST` | `/unlock` | Unlock vault with PIN (or master key) |
| `POST` | `/lock` | Lock vault and wipe session |
| `GET` | `/status` | Vault lock status + session state |
| `GET` | `/files` | List encrypted files |
| `POST` | `/encrypt` | Encrypt a file |
| `POST` | `/decrypt` | Decrypt a file |
| `DELETE` | `/files/{file_id}` | Delete encrypted file record |
| `GET` | `/passwords` | List stored credentials |
| `POST` | `/passwords` | Store new encrypted credential |
| `DELETE` | `/passwords/{id}` | Delete credential |

### Firewall  `/api/firewall`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/rules` | List all firewall rules |
| `POST` | `/rules` | Add a new rule |
| `DELETE` | `/rules/{id}` | Delete a rule |
| `GET` | `/status` | Get firewall ON/OFF state |
| `POST` | `/toggle` | Toggle firewall on or off |

### File Integrity  `/api/integrity`
| Method | Route | Description |
|:---|:---|:---|
| `POST` | `/baseline` | Create SHA-256 baseline for a folder |
| `POST` | `/scan` | Re-scan and detect changes |
| `GET` | `/alerts` | List detected integrity alerts |

### Phishing  `/api/phishing`
| Method | Route | Description |
|:---|:---|:---|
| `POST` | `/analyze` | Analyze a URL for phishing indicators |

### Network Monitor  `/api/network`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/alerts` | Parse and return Suricata eve.json alerts |

### Threat Engine  `/api/alerts`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/` | List threat alerts with risk levels |
| `GET` | `/recommendations` | Get countermeasure recommendations |
| `POST` | `/recommendations/{id}/execute` | Execute a recommended action |

### Reports  `/api/reports`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/generate` | Generate and download PDF security report |

### Security Score  `/api/security-score`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/` | Get composite weighted security score |

### Timeline  `/api/timeline`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/` | Get chronological audit event list |

### Settings  `/api/settings`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/` | Get all system settings |
| `POST` | `/` | Update a setting key/value |
| `POST` | `/backup` | Trigger manual database backup |
| `POST` | `/restore` | Restore database from backup |

### Logs  `/api/logs`
| Method | Route | Description |
|:---|:---|:---|
| `GET` | `/` | Query audit log entries from DB |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm 9+

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Linux/macOS
pip install -r requirements.txt
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`.  
Visit `http://localhost:8000/docs` for the interactive OpenAPI (Swagger) documentation.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The UI will be available at `http://localhost:5173`.

### First-Time Usage

1. Start the backend (`uvicorn main:app --reload`)
2. Start the frontend (`npm run dev`)
3. Open `http://localhost:5173`
4. Click **Register Key** to create an operator account
5. Log in with your credentials
6. Go to **Encrypted Vault** → set up your vault PIN
7. Optionally set a master recovery key in vault settings

---

## 🧪 Running Tests

```bash
cd tests
pytest test_auth.py -v          # Authentication unit tests
pytest test_mock_api.py -v      # Full API mock tests
python benchmark.py             # Performance benchmarks
```

---

## 📄 License

This project is for educational and personal use.
