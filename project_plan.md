# LogVigil — Project Development Plan

> **Project Status: ✅ v1.0 Complete**  
> All 14 development phases have been implemented and verified.

---

## High-Level Roadmap

```text
Phase -1  Planning & Design              ✅ DONE
   ↓
Phase 0   Project Setup                  ✅ DONE
   ↓
Phase 1   Authentication                 ✅ DONE
   ↓
Phase 1.5 API Design                     ✅ DONE
   ↓
Phase 2   Dashboard                      ✅ DONE
   ↓
Phase 2.5 Logging                        ✅ DONE
   ↓
Phase 3   Vault                          ✅ DONE
   ↓
Phase 4   File Integrity                 ✅ DONE
   ↓
Phase 5   Password Vault                 ✅ DONE
   ↓
Phase 6   Firewall Manager               ✅ DONE
   ↓
Phase 7   Network Monitor (Suricata)     ✅ DONE
   ↓
Phase 8   Threat Engine                  ✅ DONE
   ↓
Phase 9   Timeline                       ✅ DONE
   ↓
Phase 10  Phishing Protection            ✅ DONE (+ URL spoofing fix)
   ↓
Phase 11  Security Score                 ✅ DONE
   ↓
Phase 12  Reports                        ✅ DONE
   ↓
Phase 13  Polish                         ✅ DONE
   ↓
Phase 14  Performance Testing            ✅ DONE
   ↓
Release v1.0                             ✅ RELEASED
```

---

## Phase -1 — Planning & Design ✅

### Goal
Establish system architecture, data flow diagrams, threat models, database schemas, and wireframes.

### Completed
- ✅ Defined system architecture: FastAPI backend + React 19 frontend + SQLite database
- ✅ Cyber-themed UI/UX design with dark mode, green-on-black terminal aesthetic
- ✅ Full database ERD mapped out across 13 tables
- ✅ Threat model analysis: file storage, password vault, authentication, session management
- ✅ Documentation written in `docs/architecture.md`, `docs/api_reference.md`, `docs/threat_model.md`

---

## Phase 0 — Project Setup ✅

### Goal
Create the project scaffolding.

### Completed
- ✅ GitHub repository initialized
- ✅ README.md created
- ✅ Folder structure: `backend/`, `frontend/`, `database/`, `docs/`, `tests/`
- ✅ Python FastAPI + Uvicorn configured
- ✅ React 19 + Vite 8 configured
- ✅ SQLite database auto-init via `db.py`

### Verification
- ✅ Frontend makes `GET /` → Backend returns `{"message": "Hello LogVigil"}`

---

## Phase 1 — Authentication ✅

### Goal
User login, registration, session management, and brute-force protection.

### Implemented Features
- **Register:** PBKDF2-HMAC-SHA256 (100 000 iterations) + unique random salt per user
- **Login:** Password verification → issue random 64-char hex session token → store in `sessions` table with 24-hour expiry
- **Logout:** Delete session token from DB
- **Session Validation:** Every protected route checks token expiry
- **Brute-Force Protection:** 5 failed login attempts per username+IP → 15-minute lockout stored in `login_attempts` table
- **Anti-Enumeration:** Lockout applied regardless of whether username exists

### Security Flow
```
Register:
  Password → random salt → PBKDF2-HMAC-SHA256 (100k iterations) → store hash + salt

Login:
  Password + salt → PBKDF2 → compare hash
  Success → token = secrets.token_hex(32) → insert into sessions (expires 24h)
  Failure → increment login_attempts; if count >= 5 → lockout for 15 minutes
```

### Database Tables
- `users` (id, username, password_hash, salt)
- `sessions` (token, username, created_at, expires_at)
- `login_attempts` (username, ip_address, failed_count, lockout_until, last_attempt)

### Verification
- ✅ Wrong password rejected
- ✅ Correct password accepted + token returned
- ✅ Passwords not stored in plaintext
- ✅ 5 failed attempts → 15-min lockout

---

## Phase 1.5 — API Design ✅

### Goal
Define all backend REST API routes, Pydantic schemas, and status codes.

### Completed
- ✅ Full OpenAPI schema via FastAPI `/docs` (Swagger UI)
- ✅ All modules have typed Pydantic request/response models
- ✅ Standard HTTP status codes used: 200, 201, 400, 401, 403, 404, 500

---

## Phase 2 — Dashboard ✅

### Goal
System Overview dashboard showing live aggregated status.

### Implemented
- **Security Score** widget (composite score from all modules)
- **Firewall Status** indicator (ON/OFF)
- **Vault Status** (LOCKED / UNLOCKED)
- **Files Protected** count (from encrypted_files table)
- **Active Alerts** count (from threat engine)
- **Recent Audit Logs** feed

### Verification
- ✅ Dashboard loads after login
- ✅ Live data pulled from backend on page load

---

## Phase 2.5 — Logging ✅

### Goal
Centralized dual-sink audit logging.

### Implemented
- **`logger.py`**: Writes to both:
  - `backend/logs/logvigil.log` (flat log file with timestamps)
  - `audit_logs` SQLite table (queryable via `/api/logs`)
- Log levels: `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- All security events (login, vault unlock, firewall changes, integrity alerts) emit log entries

### Verification
- ✅ Login triggers `INFO: User 'faruk' logged in`
- ✅ Failed vault attempt triggers `WARNING`
- ✅ Lockout triggers `CRITICAL` log

---

## Phase 3 — Vault Module ✅

### Goal
File encryption/decryption with PIN-protected access and progressive lockout.

### Implemented Features

#### PIN Setup & Key Derivation
```
User sets PIN
  → PBKDF2(PIN + random pin_salt) → store pin_hash
  → PBKDF2(PIN + random vault_salt) → AES-256 key
  → Store encrypted_key_by_pin (AES key wrapped with PIN-derived key)
```

#### Vault Unlock
```
User enters PIN
  → Verify against pin_hash
  → Derive AES key from PIN + vault_salt
  → Create vault_session in DB (expires in 5 minutes of inactivity)
  → Each vault API call refreshes session TTL (touch_vault_session)
```

#### Progressive Lockout (Argon2id upgraded security service)
```
Failure 1 → No lockout (prompt for master key instead)
Failure 2 → 30-minute lockout
Failure 3 → 2-hour lockout
Failure 4+ → 24-hour lockout (admin recovery)
```

#### Master Key Recovery
```
User can set an optional Argon2id master key
  → Argon2id(master_key) → store master_key_hash
  → AES key also encrypted with master-key-derived key
  → If PIN fails → can unlock via master key
```

#### File Encryption
```
Select file → AES-256-GCM encrypt (random 12-byte nonce per file)
  → Output: nonce (12B) || ciphertext || GCM tag (16B) → .enc file
  → Record stored in encrypted_files table
```

#### Vault Session Management
- DB-persisted sessions (not in-memory)
- 5-minute inactivity timeout
- Session auto-cleaned on expiry or manual lock
- Cryptographic key material wiped from memory on lock (`wipe_vault_key`)

### Database Tables
- `vault_pins` — PIN hash, vault salt, master key hash, wrapped AES keys
- `vault_sessions` — active session tokens with expiry
- `vault_security` — failed attempt counter + lockout timestamps
- `encrypted_files` — metadata for all encrypted files

### Verification
- ✅ Encrypt file → cannot read original content
- ✅ Decrypt → original file restored
- ✅ Wrong PIN 2+ times → lockout applied
- ✅ Vault session expires after 5 minutes of inactivity

---

## Phase 4 — File Integrity Monitor ✅

### Goal
Monitor files for unauthorized changes using SHA-256 checksums.

### Implemented
```
Select folder → walk all files → SHA-256 hash each file → store baseline
Re-scan       → recalculate hashes → compare to baseline
  MODIFIED  → hash changed
  ADDED     → new file not in baseline
  DELETED   → baseline file no longer exists
  → Alert recorded in integrity_alerts table
```

- Chunk-based reading for large files (memory-efficient)
- Alerts stored with: file path, alert type, old hash, new hash, timestamp

### Database Tables
- `integrity_baselines` — baseline file hashes
- `integrity_alerts` — detected changes

### Verification
- ✅ Modify a file → MODIFIED alert appears in UI
- ✅ Add new file to folder → ADDED alert appears
- ✅ Delete a file → DELETED alert appears

---

## Phase 5 — Password Vault ✅

### Goal
Encrypted credential storage. Accessible only within an active vault session.

### Implemented
```
Store:    Enter website + username + password
          → AES-256-GCM encrypt password with vault AES key
          → hex-encoded ciphertext stored in password_vault table

Retrieve: Fetch from DB → AES-256-GCM decrypt → display plaintext
          (requires active vault_session)
```

### Database Table
- `password_vault` (id, website, username, encrypted_password)

### Verification
- ✅ Stored password cannot be read from DB without the vault key
- ✅ Restart app → login → unlock vault → passwords still retrievable

---

## Phase 6 — Firewall Manager ✅

### Goal
Manage system firewall rules via UI. Does not build a new firewall — controls ufw/iptables.

### Implemented
- Add/delete firewall rules (protocol, port, action, direction, optional IP filter)
- Toggle firewall ON/OFF (stored in `firewall_status` table)
- All rule changes logged to `audit_logs`
- Seeded with default rules: allow HTTP (80), block SSH (22)

### Database Tables
- `firewall_rules` (id, protocol, port, action, direction, description, ip_address)
- `firewall_status` (enabled)

### Verification
- ✅ Add rule → appears in rule list
- ✅ Delete rule → removed from list
- ✅ Toggle firewall → status changes in dashboard

---

## Phase 7 — Network Monitor (Suricata) ✅

### Goal
Integrate Suricata IDS and display real-time alerts.

### Implemented
```
Internet → Suricata → /var/log/suricata/eve.json
         → Python parser reads & classifies events
         → Severity: HIGH / MEDIUM / LOW
         → Returns structured alert feed to frontend
```

- Falls back gracefully if Suricata is not installed (returns empty feed)
- Alert feed shown in Network Monitor page with timestamps and rule signatures

### Verification
- ✅ Suricata test alert → appears in dashboard
- ✅ Graceful fallback when Suricata is offline

---

## Phase 8 — Threat Engine ✅

### Goal
Intelligent alert triage — not just raw logs but classified threats with countermeasures.

### Implemented
```
Suricata Alert (e.g., "Possible Malware C2 Traffic")
  → Classified as HIGH risk
  → Countermeasure generated: "Block source IP in firewall"
  → Recommendation stored in threat_recommendations table
  → Operator can click "Execute" to apply action
```

- Recommendation types: BLOCK_IP, TERMINATE_PROCESS, ISOLATE_HOST, UPDATE_SIGNATURES
- Status tracked: PENDING → EXECUTED

### Database Table
- `threat_recommendations` (id, threat_id, title, description, action_type, action_payload, status)

### Verification
- ✅ Feed simulated alert → correct risk level and recommendation generated
- ✅ Execute recommendation → status changes to EXECUTED

---

## Phase 9 — System Timeline ✅

### Goal
Chronological event feed across all system modules.

### Implemented
- Aggregates all `audit_logs` rows ordered by timestamp
- Displayed as a vertical timeline in the UI with level-colour coding
- Events include: logins, vault unlocks, firewall changes, integrity alerts, threat detections

### Verification
- ✅ Events appear in correct chronological order
- ✅ Each event shows level (INFO / WARNING / ERROR / CRITICAL), message, timestamp

---

## Phase 10 — Phishing Protection ✅

### Goal
Analyze URLs for phishing and spoofing indicators. Return a 0–100 safety score.

### Implemented Detection Vectors

| Check | Penalty | Description |
|:---|:---|:---|
| No HTTPS | −20 | URL starts with `http://` |
| Typosquatting | −40 | Domain contains `goog1e`, `paypa1`, `faceb00k` |
| Raw IP domain | −30 | Domain is an IP address (e.g., `192.168.1.1`) |
| `@` sign in URL | −40 | Credential injection / URL spoofing attack |
| Suspicious keywords | −15 | `login`, `verify`, `update-account`, `banking` |
| Blacklisted domain | Score → **0** | Contains `malicious`, `phish`, `securevault-update` |

### URL Spoofing Fix (post-release patch)
The `@` sign in a URL authority section (`https://example.com@192.0.2.10/login`) is a credential-injection attack — the browser connects to `192.0.2.10` while displaying `example.com`. The phishing engine now:
1. Detects `@` in the URL host section
2. Extracts the **real host** (after `@`) before IP-detection
3. Applies −40 penalty for the `@`-sign spoofing indicator

### Risk Levels
```
80–100 → LOW
50–79  → MEDIUM
0–49   → HIGH
```

### API Response Fields
```json
{
  "url": "...",
  "safety_score": 15.0,
  "risk_level": "HIGH",
  "details": {
    "https_enabled": true,
    "on_blacklist": false,
    "typosquatting_detected": false,
    "ip_address_url": true,
    "at_sign_in_url": true,
    "suspicious_keywords": true
  }
}
```

### Verification
- ✅ `https://google.com` → 100 / LOW
- ✅ `http://goog1e.com/verify-account` → 25 / HIGH (typosquatting + no HTTPS + keyword)
- ✅ `https://securevault-update.com/login` → 0 / HIGH (blacklisted)
- ✅ `https://example.com@192.0.2.10/login` → 15 / HIGH (IP + @ spoofing + keyword)

---

## Phase 11 — Security Score ✅

### Goal
Composite weighted security score from all modules.

### Implemented
Aggregates live data from:
- Firewall ON/OFF status
- Active integrity alerts count
- Vault setup state
- Threat alert severity counts
- Network monitor alert count

Returns a single 0–100 score displayed on the System Overview dashboard.

### Verification
- ✅ Disable firewall → overall score decreases
- ✅ Integrity alerts detected → score decreases

---

## Phase 12 — Reports ✅

### Goal
Generate downloadable PDF security reports.

### Report Contents
- System security score
- Firewall status and active rules
- File integrity: files protected + recent alerts
- Threat engine: active threats + recommendations
- Audit log summary
- Generated timestamp and operator name

### Verification
- ✅ Click "Generate Report" → PDF downloaded
- ✅ PDF contains accurate current system state

---

## Phase 13 — Polish ✅

### Implemented
- ✅ Full dark cyber-themed UI (green-on-black terminal aesthetic)
- ✅ Smooth CSS animations and hover effects on all interactive elements
- ✅ Sidebar navigation with active-state highlighting
- ✅ Live system clock in top bar
- ✅ Gateway connection status indicator
- ✅ Notification system for key events
- ✅ Settings page: dark mode toggle, notification preferences, backup frequency
- ✅ Automated backup scheduler (DAILY / WEEKLY / MONTHLY) with APScheduler
- ✅ Database backup/restore via UI

---

## Phase 14 — Performance Testing ✅

### Implemented
- **`tests/benchmark.py`**: AES-256 encryption throughput on large files
- **`tests/test_mock_api.py`**: Full API endpoint test suite
- **`tests/test_auth.py`**: Authentication edge-case tests

### Results
- ✅ AES-256-GCM encryption handles large files without memory leaks
- ✅ All API endpoints respond within acceptable latency under mock load
- ✅ DB schema handles concurrent reads/writes without corruption

---

## Release v1.0 ✅

### Deliverables
- ✅ Full backend: FastAPI + SQLite with 13 database tables
- ✅ Full frontend: React 19 + 10 UI pages
- ✅ Complete REST API documented at `/docs`
- ✅ Security hardening: Argon2id master key, PBKDF2 passwords, AES-256-GCM encryption, progressive lockout, brute-force protection, phishing URL spoofing detection
- ✅ Test suite: unit tests + mock API tests + benchmarks

---

## Testing Strategy

After every phase, four test categories were applied:

| Test Type | Description |
|:---|:---|
| **Functional Test** | Does the feature work as expected end-to-end? |
| **Security Test** | Is sensitive data protected (encrypted/hashed, not plaintext)? |
| **Edge Case Test** | Empty input, very large files, invalid/malformed data, expired sessions |
| **Regression Test** | Did the new feature break any previously working functionality? |

---

## Folder Structure

```text
CryptGuard/
├── backend/
│   ├── auth/               # Login, register, logout, session token
│   ├── vault/              # File encryption, password vault, PIN/master-key
│   ├── firewall/           # Firewall rule CRUD + toggle
│   ├── integrity/          # SHA-256 baseline + change detection
│   ├── phishing/           # URL phishing analyzer
│   ├── network/            # Suricata eve.json parser
│   ├── alerts/             # Threat engine + recommendations
│   ├── reports/            # PDF generation
│   ├── security_score/     # Composite score aggregator
│   ├── timeline/           # Audit event timeline
│   ├── settings/           # Preferences + backup scheduler
│   ├── main.py             # FastAPI app entry + lifespan hooks
│   ├── db.py               # SQLite schema + connection helper
│   ├── logger.py           # Dual-sink audit logger
│   ├── security_service.py # Argon2id, vault sessions, brute-force
│   ├── auth_service.py     # PBKDF2 password utilities
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── pages/          # 10 UI pages
│       ├── components/     # Sidebar navigation
│       ├── App.jsx         # Auth guard + routing
│       └── App.css         # Cyber dark theme
├── database/
│   └── logvigil.db         # Auto-created SQLite DB
├── tests/
│   ├── test_auth.py
│   ├── test_mock_api.py
│   └── benchmark.py
└── docs/
    ├── architecture.md
    ├── api_reference.md
    └── threat_model.md
```
