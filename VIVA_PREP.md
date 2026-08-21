# LogVigil — Viva Preparation Guide
### Simple, clear answers grounded in your actual code

---

> **How to use this guide:**
> Read each answer out loud. Know the file name for every feature.
> The format for every topic is: **What → Why → How → Where → Input → Output**

---

## 📁 Quick File Reference (Know These Cold)

| Feature | File | Key Function / Class |
|---|---|---|
| Password Hashing | `backend/auth_service.py` | `hash_password()`, `verify_password()` |
| Auth Routes (Login/Register) | `backend/auth/router.py` | `login()`, `register()`, `_create_session()` |
| Brute-Force Protection | `backend/security_service.py` | `check_login_lockout()`, `record_login_failure()` |
| Vault Encryption | `backend/vault/router.py` | `derive_key()`, `encrypt_vault_key()`, `decrypt_vault_key()` |
| Argon2id (Master Key) | `backend/security_service.py` | `hash_master_key()`, `verify_master_key()` |
| File Integrity Monitor | `backend/integrity/router.py` | `compute_sha256()`, `walk_folder()` |
| Firewall Manager | `backend/firewall/router.py` | `run_firewall_command()`, `get_firewall_backend()` |
| Suricata / Network | `backend/network/router.py` | `get_network_alerts()`, `check_suricata_service_active()` |
| Threat Engine | `backend/alerts/router.py` | `sync_threat_recommendations()` |
| Phishing Detector | `backend/phishing/router.py` | `analyze_url()` |
| Security Score | `backend/security_score/router.py` | `get_security_score()` |
| Logging | `backend/logger.py` | `log_event()` |
| Database Schema | `backend/db.py` | `init_db()` |
| PDF / Backup | `backend/reports/router.py` | — |
| Settings / Scheduler | `backend/settings/router.py` | — |

---

## 1. Overall Project (8 Questions)

---

**Q: What is LogVigil?**

LogVigil is a local Linux host security monitoring and log analysis platform.
It runs on your own Linux machine and gives you a single dashboard to monitor
file integrity, network threats, firewall rules, login security, and encrypted
credential storage — all from one browser-based interface.

---

**Q: What problem does LogVigil solve?**

Most security tools are expensive, cloud-based, or require expert knowledge to
use. LogVigil solves this by being:
- **Free and local** — your data never leaves your machine
- **All-in-one** — no need to run 5 separate tools
- **Simple** — a clean web interface that any user can understand

---

**Q: Why did you choose Linux host security?**

Linux is the most common operating system for servers, cloud machines, and
developer workstations. It is also the most targeted by attackers. Linux
provides the system tools (UFW, iptables, Suricata, systemd) that LogVigil
talks to directly.

---

**Q: Why did you make it a local security platform?**

Because sensitive security data — file hashes, encryption keys, audit logs —
should never be sent to the cloud. A local platform means:
- No network dependency
- No third-party data access
- Faster response times
- Works even when the internet is down

---

**Q: What are the main features of LogVigil?**

1. **Authentication** — secure login with PBKDF2 + brute-force lockout
2. **Cryptographic Vault** — AES-256-GCM encrypted credential storage
3. **File Integrity Monitoring (FIM)** — detects modified/added/deleted files
4. **Firewall Manager** — add/remove UFW or iptables rules from the UI
5. **Network Monitoring (NIDS)** — reads Suricata alerts from `eve.json`
6. **Threat Engine** — automated recommendations (BLOCK_IP, FIREWALL_ENABLE)
7. **Phishing Detector** — heuristic URL analysis and scoring
8. **Security Score** — real-time aggregated score from all modules
9. **Audit Logging** — every action logged to file and SQLite
10. **PDF Reports & Backups** — scheduled exports and data backup

---

**Q: Why did you combine all these security features into one system?**

Because security is not effective in isolation. A firewall alert should trigger
a threat response. A file change should affect the security score. A login
failure should be logged. LogVigil connects all these modules so they work
together automatically instead of in separate silos.

---

**Q: What makes LogVigil lightweight?**

- **Backend:** FastAPI (Python) — extremely fast and minimal
- **Database:** SQLite — no separate database server needed, just a single file
- **Frontend:** React (Vite) — runs in any browser, no native app install
- **No cloud:** Everything runs on localhost (port 8000 backend, 5173 frontend)

---

**Q: What is the overall workflow of LogVigil?**

```
User opens browser → Login (PBKDF2 auth) → Session token created
        ↓
Dashboard loads → All modules query the FastAPI backend (port 8000)
        ↓
FIM scans folders → Suricata writes alerts → Firewall status checked
        ↓
Threat Engine reads alerts → generates recommendations
        ↓
Security Score calculated from all modules → displayed on dashboard
        ↓
Every action → logged to logvigil.log + SQLite audit_logs table
```

> **Follow-up: "Show me where these features are implemented."**
> Point to the file reference table at the top. Know the file name and function for each feature.

---

## 2. Authentication & Session Security (8 Questions)

**File:** `backend/auth_service.py` (hashing) + `backend/auth/router.py` (login logic)
**Brute-force:** `backend/security_service.py`

---

**Q: How does your authentication system work?**

1. User submits username + password
2. Backend looks up the user's stored `salt` from the `users` table in SQLite
3. `hash_password()` in `auth_service.py` runs PBKDF2-HMAC-SHA256 with 100,000 iterations
4. The result is compared to the stored hash
5. If it matches → a 64-character hex session token is created with `secrets.token_hex(32)` and stored in the `sessions` table
6. The token is returned to the frontend and sent with every future request as a `Bearer` header

---

**Q: Why did you use PBKDF2?**

PBKDF2 (Password-Based Key Derivation Function 2) makes password cracking
extremely slow. Instead of just hashing the password once (which can be cracked
quickly), PBKDF2 applies the hash function **100,000 times**.
Even if an attacker steals the database, cracking one password takes seconds
on a normal hash but **minutes to hours** with PBKDF2.

Actual code in `auth_service.py`:
```python
hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
```

---

**Q: Why SHA-256?**

SHA-256 is a cryptographic hash function that:
- Produces a fixed 256-bit (32-byte) output
- Is deterministic — same input always gives same output
- Is one-way — you cannot reverse it to get the original password
- Is collision-resistant — two different inputs almost never produce the same output
- Is the industry standard approved by NIST

---

**Q: What is a salt?**

A salt is a random value added to the password before hashing.
Without a salt, two users with the same password would have the same hash.
An attacker with a **rainbow table** (pre-computed hash database) could crack
both instantly.

With a salt, even two identical passwords produce completely different hashes.
The salt is generated with `os.urandom(16)` — 16 random bytes — in `auth_service.py`.

---

**Q: Why is a unique salt generated for every user?**

Because if all users shared the same salt, the salt provides no protection.
An attacker could build a rainbow table using the known salt and crack all
passwords at once. A unique salt per user forces the attacker to attack
each password individually.

---

**Q: Why did you choose 100,000 iterations?**

This is the **NIST recommended minimum** for PBKDF2-SHA256.
100,000 iterations means the hash function runs 100,000 times on every login
attempt. This takes ~0.1–0.3 seconds on a server — acceptable for a real user.
But for an attacker trying billions of passwords, it multiplies the time
needed by 100,000.

---

**Q: How is the session created after login?**

In `auth/router.py`, the `_create_session()` function:
1. Generates a cryptographically random 64-character hex token: `secrets.token_hex(32)`
2. Calculates the expiry time: `now + 24 hours`
3. Inserts it into the `sessions` table: `(token, username, created_at, expires_at)`
4. Returns the token to the frontend

The frontend stores the token in `localStorage` and sends it as `Authorization: Bearer <token>` with every API request.

---

**Q: How does your brute-force protection work?**

Implemented in `security_service.py`:
- Failed login attempts are tracked per username + IP address in a `login_attempts` table
- `LOGIN_MAX_ATTEMPTS = 5` — after 5 consecutive failures, the account is locked
- `LOGIN_LOCKOUT_SECONDS = 900` — the lockout lasts **15 minutes**
- `check_login_lockout()` is called **before** even looking up the user — this prevents timing attacks
- `record_login_failure()` increments the counter
- `reset_login_attempts()` clears the counter on successful login

> **"What happens if I enter the wrong password 5 times?"**
> The `login_attempts` table records each failure with username + IP.
> After the 5th failure, `check_login_lockout()` returns `True` and the API
> returns HTTP 429 with the remaining lockout seconds.
> The frontend shows a countdown timer. The lockout lasts 15 minutes.

> **"Why not store the password directly?"**
> Storing plain text passwords is extremely dangerous. If the database is stolen,
> every user's password is immediately exposed. PBKDF2 converts the password into
> a derived value that cannot be reversed, making it useless without a brute-force
> attack that takes enormous time.

---

## 3. Cryptographic Vault (10 Questions)

**File:** `backend/vault/router.py`
**Argon2id:** `backend/security_service.py`

---

**Q: How does your vault work?**

The vault stores two types of secrets: encrypted files and login credentials.
The security model uses **envelope encryption**:

```
PIN entered by user
      ↓
PBKDF2 (100,000 iterations, SHA-256) → PIN-derived key (32 bytes)
      ↓
This key decrypts the "master vault key" (randomly generated AES-256 key)
      ↓
The master vault key encrypts/decrypts all actual vault data
```

All encryption uses **AES-256-GCM**.

---

**Q: Why did you use AES-256-GCM?**

AES-256-GCM is the gold standard for symmetric encryption because:
- **AES** is approved by NIST and used by governments worldwide
- **256** means the key is 256 bits — one of the strongest key sizes available
- **GCM** (Galois/Counter Mode) provides both:
  - **Confidentiality** — data is encrypted, unreadable without the key
  - **Integrity** — if anyone modifies the ciphertext, decryption fails (authentication tag)

Without GCM, an attacker could modify encrypted data without detection.

---

**Q: What is AES?**

AES stands for Advanced Encryption Standard. It is a symmetric encryption
algorithm — the same key is used to encrypt and decrypt. It works by
transforming data through multiple rounds of mathematical operations
(substitution, permutation, mixing) using a fixed key. It is extremely
fast in hardware and software and is the world standard for encryption.

---

**Q: What does 256 mean in AES-256?**

It means the encryption key is **256 bits long** (32 bytes).
This gives 2^256 possible keys — a number so large that even all the
computers on Earth working together for billions of years could not try them all.
AES also comes in 128-bit and 192-bit variants, but 256-bit is the strongest.

---

**Q: What does GCM provide?**

GCM stands for Galois/Counter Mode. It provides:
1. **Encryption** — converts plaintext to ciphertext using a counter-based stream
2. **Authentication tag** — a 16-byte tag generated during encryption that proves
   the data was not modified. If even one byte changes, decryption produces an error.
   This is called **Authenticated Encryption**.

In vault code: `aesgcm.encrypt(nonce, vault_key, None)` — the `AESGCM` class
handles both encryption and the authentication tag automatically.

---

**Q: What is envelope encryption?**

Envelope encryption is a technique where:
1. A **Data Encryption Key (DEK)** — the vault key — encrypts the actual data
2. A **Key Encryption Key (KEK)** — derived from the user's PIN — encrypts the DEK

This way, if the user changes their PIN, you only re-encrypt the small DEK,
not all the data. The DEK itself is randomly generated:
`vault_key = secrets.token_bytes(32)` — a random 256-bit AES key.

---

**Q: Why do you generate a separate master AES key?**

Because a randomly generated key is cryptographically much stronger than a
key derived directly from a PIN (which has limited entropy — users choose
short, predictable PINs). The master key is truly random (32 bytes from
`secrets.token_bytes(32)`), while the PIN-derived key only needs to protect
the small master key, not all the data directly.

---

**Q: How is the PIN converted into a cryptographic key?**

In `vault/router.py`, the `derive_key()` function:
```python
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=vault_salt, iterations=100000)
return kdf.derive(pin.encode('utf-8'))
```
The PIN is passed through PBKDF2-HMAC-SHA256 with 100,000 iterations and a
random per-user salt, producing a 32-byte (256-bit) AES key.

---

**Q: Why did you use PBKDF2 again for the PIN?**

For the same reason as the password: a raw PIN like "1234" is not a valid
AES key. PBKDF2 stretches it into a proper cryptographic key of the exact
length needed (32 bytes) while also making brute-force attacks slow.

---

**Q: What is Argon2id and why did you use it?**

Argon2id is a **memory-hard** password hashing algorithm that won the
Password Hashing Competition in 2015. It is used in LogVigil for the
**Master Key** (emergency recovery key) in `security_service.py`.

Configuration in the code:
```python
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
```
- `time_cost=3` — 3 iterations
- `memory_cost=65536` — requires **64 MB of RAM** per attempt
- `parallelism=2` — uses 2 CPU threads

**Why Argon2id over PBKDF2 for the master key?**
Argon2id is memory-hard — it forces the attacker to use large amounts of RAM.
GPU-based cracking is much harder because GPUs have limited memory per core.
PBKDF2 only needs CPU time, so GPUs can crack it much faster.

> **"Explain the complete vault process."**
> 1. User sets a PIN → `derive_key()` generates a 32-byte PIN-derived key using PBKDF2
> 2. A random 32-byte master vault key is generated: `secrets.token_bytes(32)`
> 3. The PIN-derived key encrypts the master vault key using AES-GCM: `encrypt_vault_key()`
> 4. The encrypted master vault key is stored in the database
> 5. When the user unlocks the vault, the PIN is re-derived → decrypts the master key
> 6. The master key then encrypts/decrypts all files and credentials

> **"What happens if the user forgets the PIN?"**
> The Master Key (set separately during vault setup) is hashed with Argon2id.
> The user can authenticate with the master key using `derive_key_from_master_key()`
> in vault/router.py to recover access.

> **"Why not encrypt everything directly with the PIN?"**
> Because the PIN has low entropy. A PIN like "1234" has only 10,000 possibilities.
> The randomly generated master AES key has 2^256 possibilities. So we use the PIN
> only to protect the small master key, not the data directly.

---

## 4. File Integrity Monitoring (8 Questions)

**File:** `backend/integrity/router.py`
**Key functions:** `compute_sha256()`, `walk_folder()`

---

**Q: What is File Integrity Monitoring?**

FIM detects unauthorized changes to files. It takes a snapshot (baseline) of
a file's cryptographic hash. Later, it re-computes the hash and compares.
If the hash changed, the file was modified. If a file is gone, it was deleted.
If a new file appeared, it was added.

---

**Q: Why did you use SHA-256?**

SHA-256 is:
- **Deterministic** — the same file always produces the same hash
- **Collision-resistant** — two different files almost never produce the same hash
- **Sensitive** — even changing one byte of a file completely changes the hash
- **One-way** — you cannot reconstruct the file from its hash

This makes it perfect for detecting file tampering.

---

**Q: How does your FIM detect a modified file?**

From `integrity/router.py`, the `compute_sha256()` function reads the file in
64 KB chunks and feeds each chunk into a `hashlib.sha256()` object.
The final `hexdigest()` is a 64-character hex string unique to that file's content.

This hash is stored in the `integrity_baselines` table in SQLite.
When a scan runs, the current hash is compared to the stored hash.
If they differ → a `MODIFIED` alert is generated in `integrity_alerts`.

---

**Q: What is a baseline?**

A baseline is the first snapshot of a file's hash, taken when the file is
known to be clean and trusted. All future comparisons are made against this
baseline. It is stored in the `integrity_baselines` table:
`(file_path, sha256_hash, file_size, folder_path, scanned_at)`.

---

**Q: What happens when a new file is created?**

During a scan, `walk_folder()` discovers all files in the monitored directory.
Any file that exists on disk but has **no entry in the baseline** is flagged as
**ADDED** — it appeared after the baseline was established.

---

**Q: What happens when a file is deleted?**

Any file that exists in the baseline but is **no longer found on disk** is
flagged as **DELETED**. The baseline still has the record, but the file path
no longer resolves to a real file.

---

**Q: Why do you process files in 64 KB chunks?**

```python
chunk = f.read(65536)  # 64 KB chunks for large file support
```

If you load an entire large file (e.g., a 10 GB log file) into memory at once,
the system could run out of RAM and crash. Processing in 64 KB chunks means
only 64 KB is ever in memory at one time. The SHA-256 object accepts chunks
incrementally via `sha256.update(chunk)`, producing the same final hash.

---

**Q: Why not load the entire file into memory?**

For the same reason: large files would crash or slow down the system.
Chunk processing is the standard practice for hashing large files efficiently.

> **"Explain MODIFIED, ADDED and DELETED."**
>
> | Status | Meaning |
> |---|---|
> | `MODIFIED` | File exists on disk but its SHA-256 hash differs from the baseline |
> | `ADDED` | File exists on disk but was not in the baseline — appeared after setup |
> | `DELETED` | File was in the baseline but no longer exists on disk |

---

## 5. Firewall Manager (7 Questions)

**File:** `backend/firewall/router.py`
**Key functions:** `get_firewall_backend()`, `run_firewall_command()`

---

**Q: What is a firewall?**

A firewall is a security system that controls incoming and outgoing network
traffic based on rules. It acts as a gatekeeper — allowing trusted traffic
and blocking suspicious or unauthorized connections.

---

**Q: Why did you implement a Firewall Manager?**

To give the user control over network security from the LogVigil dashboard
without needing to know terminal commands. The user can enable/disable the
firewall and add rules (block/allow specific IPs, ports, protocols) through
the web interface.

---

**Q: What is UFW?**

UFW stands for **Uncomplicated Firewall**. It is a user-friendly front-end for
iptables, designed for Ubuntu/Debian Linux. LogVigil detects whether UFW is
installed using `shutil.which("ufw")` in `firewall/router.py` and uses it if
available.

---

**Q: What is iptables?**

iptables is the underlying Linux kernel firewall tool. It directly manages
packet filtering rules in the kernel's netfilter framework. UFW is a wrapper
around iptables. LogVigil falls back to iptables if UFW is not installed.

---

**Q: What's the difference between UFW and iptables?**

| | UFW | iptables |
|---|---|---|
| Complexity | Simple, beginner-friendly | Complex, very powerful |
| Example | `ufw allow 80/tcp` | `iptables -A INPUT -p tcp --dport 80 -j ACCEPT` |
| Common use | Desktop / simple servers | Advanced servers |

LogVigil auto-detects which is available: `get_firewall_backend()` in `firewall/router.py`.

---

**Q: How does your application add/remove firewall rules?**

The `run_firewall_command()` function in `firewall/router.py` executes system
commands using `subprocess.run()` with a timeout of 5 seconds.
For UFW, a block rule looks like: `sudo ufw deny from 192.168.1.50`
For iptables: `sudo iptables -A INPUT -s 192.168.1.50 -j DROP`
Rules are also saved to the `firewall_rules` table in SQLite for persistence.

---

**Q: What happens when the user blocks an IP?**

1. User enters an IP in the Firewall UI and clicks Block
2. Frontend sends a POST to `/api/firewall/rules`
3. `run_firewall_command()` executes the appropriate UFW/iptables command
4. The rule is saved to the `firewall_rules` SQLite table
5. `log_event()` records the action in `logvigil.log` and `audit_logs`
6. The Threat Engine can also trigger this automatically via `FIREWALL_BLOCK`

> **"What are TCP and UDP?"**
> - **TCP** (Transmission Control Protocol) — reliable, connection-based. Used for web (HTTP/HTTPS), SSH, email.
> - **UDP** (User Datagram Protocol) — fast, connectionless. Used for DNS, video streaming, gaming.
>
> **"What is IN and OUT?"**
> - **INBOUND** — traffic coming into your machine
> - **OUTBOUND** — traffic going out from your machine

---

## 6. Suricata Network Monitoring (8 Questions)

**File:** `backend/network/router.py`
**Key path:** `/var/log/suricata/eve.json`

---

**Q: What is Suricata?**

Suricata is an open-source **Network Intrusion Detection System (NIDS)**.
It monitors all network traffic in real-time and matches it against thousands
of known attack signatures (rules). When it detects suspicious traffic,
it writes an alert to a log file called `eve.json`.

---

**Q: Is Suricata a firewall?**

No. Suricata only **detects** — it does not block traffic by itself.
A firewall (UFW/iptables) **blocks** traffic.
Suricata tells you what suspicious traffic was seen; the firewall stops it.
In LogVigil, the Threat Engine connects the two:
Suricata detects → Threat Engine recommends → Firewall blocks.

---

**Q: What is NIDS?**

NIDS stands for **Network Intrusion Detection System**. It passively monitors
network traffic and generates alerts when it matches known attack patterns.
Examples: port scans, SQL injection attempts, malware communication,
suspicious user agents.

---

**Q: How does LogVigil communicate with Suricata?**

LogVigil:
1. Checks if Suricata is running: `subprocess.run(["systemctl", "is-active", "suricata"])` in `network/router.py`
2. Can start/stop it: `sudo systemctl start/stop suricata`
3. Reads its output from `/var/log/suricata/eve.json`

---

**Q: What is eve.json?**

`eve.json` is Suricata's unified alert log file at `/var/log/suricata/eve.json`.
Every time Suricata detects something suspicious, it writes a JSON record
containing: timestamp, source IP, destination IP, alert category, alert message,
protocol, port, and payload snippet.

---

**Q: What information does Suricata provide?**

Each alert contains:
- `source_ip` — where the attack is coming from
- `dest_ip` — which machine was targeted
- `category` — type of threat (e.g., "Potentially Bad Traffic")
- `message` — specific rule that triggered (e.g., "ET MALWARE Suspicious User Agent")
- `risk_level` — HIGH / MEDIUM / LOW
- `payload_snippet` — part of the actual packet data

---

**Q: How does LogVigil read Suricata alerts?**

The `get_network_alerts()` function in `network/router.py` opens `eve.json`,
reads each line (each line is one JSON event), filters for `event_type: "alert"`,
and returns the results. If Suricata is not running or `eve.json` doesn't exist
(development mode), it falls back to `mock_alerts` defined in the same file.

---

**Q: What happens when a new alert arrives?**

1. Suricata writes the alert to `eve.json`
2. LogVigil's `/api/network/alerts` reads the file on each request
3. The Threat Engine calls `get_network_alerts()` and generates recommendations
4. The Security Score is automatically reduced based on active alerts

> **"Explain the complete flow."**
> ```
> Network traffic → Suricata rule match → Alert written to /var/log/suricata/eve.json
>       ↓
> network/router.py: get_network_alerts() reads eve.json
>       ↓
> alerts/router.py: sync_threat_recommendations() analyzes each alert
>       ↓
> HIGH risk → FIREWALL_BLOCK recommendation generated
> MEDIUM risk → FIREWALL_ENABLE recommendation generated
>       ↓
> User approves → run_firewall_command() blocks the IP in UFW/iptables
>       ↓
> log_event() records the action in audit_logs + logvigil.log
> ```

---

## 7. Threat Engine (8 Questions)

**File:** `backend/alerts/router.py`
**Key function:** `sync_threat_recommendations()`

---

**Q: What is the Threat Engine?**

The Threat Engine is the intelligence layer of LogVigil. It reads network
alerts from Suricata, analyzes them, classifies the threat level, and
automatically generates recommended security responses.

---

**Q: Why do you need a Threat Engine?**

Raw alerts from Suricata are just text. Without the Threat Engine, the user
would have to read each alert and manually decide what to do. The Threat Engine
automates analysis and presents clear, actionable recommendations that the user
can approve with one click.

---

**Q: How does it analyze Suricata alerts?**

In `sync_threat_recommendations()` in `alerts/router.py`:
```python
msg_upper = alert["message"].upper()
if "MALWARE" in msg_upper or risk_level == "HIGH":
    action_type = "FIREWALL_BLOCK"   # Block the source IP
elif "SQL INJECTION" in msg_upper or risk_level == "MEDIUM":
    action_type = "FIREWALL_ENABLE"  # Ensure firewall is on
```
It checks keywords in the alert message and the risk level to decide the response.

---

**Q: How does it classify threats?**

| Alert content | Action |
|---|---|
| "MALWARE" in message, or risk = HIGH | `FIREWALL_BLOCK` — block source IP |
| "SQL INJECTION", or risk = MEDIUM | `FIREWALL_ENABLE` — ensure firewall is on |
| Other alerts | `FIREWALL_ENABLE` — general check |

---

**Q: How does BLOCK_IP work?**

When the user approves a `FIREWALL_BLOCK` recommendation:
1. `execute_recommendation()` in `alerts/router.py` is called
2. It calls `create_firewall_rule()` from `firewall/router.py`
3. This runs `sudo ufw deny from <source_ip>` (or iptables equivalent)
4. The rule is saved to the `firewall_rules` SQLite table
5. The recommendation status is updated to `EXECUTED` in `threat_recommendations`

---

**Q: How does TERMINATE_PROCESS work?**

The Threat Engine can recommend killing a suspicious process by PID using
`subprocess.run(["sudo", "kill", "-9", str(pid)])`. This stops a process
that is communicating with known malicious hosts.

---

**Q: How does ISOLATE_HOST work?**

ISOLATE_HOST is the most drastic response. It blocks all inbound and outbound
traffic on the machine using firewall rules, effectively cutting it off from
the network. This is used when a serious compromise is suspected.

---

**Q: Why is automated response better than only generating alerts?**

Alerts without action are useless if the user does not respond in time.
An automated recommendation with one-click execution means:
- Faster response time (seconds vs. minutes)
- No need for the user to know terminal commands
- Consistent, policy-driven responses
- Every action is still logged for audit purposes

> **"Give me an example of a real attack."**
> Suricata detects: "ET MALWARE Suspicious User Agent" from IP `192.168.1.105` (HIGH)
> → `sync_threat_recommendations()` creates a `FIREWALL_BLOCK` recommendation
> → User clicks "Execute" in the Threats dashboard
> → `run_firewall_command(["sudo", "ufw", "deny", "from", "192.168.1.105"])` runs
> → IP is blocked at the system level
> → `log_event()` records the block in SQLite and `logvigil.log`

---

## 8. Phishing Detection (9 Questions)

**File:** `backend/phishing/router.py`
**Key function:** `analyze_url()`

---

**Q: What is phishing?**

Phishing is a social engineering attack where an attacker tricks a user into
visiting a fake website that looks like a legitimate one, stealing their
credentials or installing malware. Example: `paypa1.com` instead of `paypal.com`.

---

**Q: How does your phishing detector work?**

The `analyze_url()` function applies multiple heuristic checks to a URL and
produces a **safety score from 0 to 100**. The more red flags found, the lower
the score.

Score thresholds:
- **≥ 80** → LOW risk (safe)
- **50–79** → MEDIUM risk (suspicious)
- **< 50** → HIGH risk (likely phishing)

---

**Q: What is heuristic detection?**

Heuristic means "rule-based pattern matching" — detecting threats based on
known suspicious patterns rather than a fixed list. For example, "if the URL
contains @ in the host, it's suspicious" is a heuristic. It catches new
phishing URLs not in any blacklist yet.

---

**Q: Why don't you simply use a blacklist?**

Blacklists are reactive — they only catch known bad URLs. Attackers can
register new domains every day. Heuristic detection catches URLs that look
suspicious **even if they've never been seen before**.

---

**Q: What is URL spoofing / @ spoofing?**

In a URL like `https://google.com@192.0.2.10/login`:
- Everything before `@` is treated as credentials (username:password)
- The actual host (destination) is **after `@`** — which is `192.0.2.10`

So the user sees "google.com" but is actually sent to a hacker's server.
LogVigil detects this with:
```python
at_sign_in_url = "@" in raw_host
domain = raw_host.split("@")[-1]  # Always use real host (after @)
score -= 40.0  # Heavy penalty
```

---

**Q: What is typosquatting?**

Typosquatting is registering a domain that looks visually similar to a
legitimate one. Examples detected in `phishing/router.py`:
```python
typosquatting_detected = "goog1e" in domain or "paypa1" in domain or "faceb00k" in domain
score -= 40.0
```
- `goog1e.com` — uses `1` (one) instead of `l` (letter L)
- `paypa1.com` — uses `1` instead of `l`
- `faceb00k.com` — uses `0` (zero) instead of `o`

---

**Q: Why is a raw IP address suspicious?**

Legitimate websites use domain names (`google.com`), not raw IPs.
A URL like `http://192.168.1.100/login` is almost always a phishing or malware
server — attackers use IPs to avoid domain registration and make tracing harder.
```python
ip_address_url = all(c.isdigit() or c == '.' for c in domain)
score -= 30.0
```

---

**Q: How does your phishing score work?**

```
Start:                       100 points
No HTTPS:                    -20 points
Typosquatting found:         -40 points
Raw IP address:              -30 points
@ spoofing detected:         -40 points
Suspicious keywords:         -15 points  (login, verify, banking, update-account)
On blacklist:                → score = 0 immediately
Minimum score:               0
```

---

> **"Is https://google.com@192.0.2.10/login suspicious? Why?"**
> Yes — HIGH risk.
> - `@` in host → at_sign_in_url = True → **-40 points**
> - Real destination is `192.0.2.10` (raw IP) → **-30 points**
> - "login" is suspicious keyword → **-15 points**
> - Total: 100 - 40 - 30 - 15 = **15 → HIGH risk**

> **"Why is paypa1.com suspicious?"**
> The `1` (digit one) is visually identical to `l` (letter L) in many fonts.
> This is classic typosquatting. `"paypa1" in domain` detects it → -40 points.

> **"Why does HTTP lose points?"**
> HTTP does not encrypt traffic. Any data (passwords, tokens) sent over HTTP can
> be intercepted by anyone on the network. Phishing sites often avoid HTTPS to
> save cost/effort.

---

## 9. Security Score (6 Questions)

**File:** `backend/security_score/router.py`
**Key function:** `get_security_score()`

---

**Q: What is the Security Score?**

A single number from 0 to 100 representing the overall security health of the
system at any given moment. It aggregates the status of all security modules
into one easy-to-read indicator.

---

**Q: How is the score calculated?**

The score is the **average of 5 component scores** (from the actual code):

```python
overall_score = int((firewall_score + vault_score + integrity_score + network_score + password_score) / 5)
```

| Component | Good state | Bad state |
|---|---|---|
| **Firewall** | 100 (enabled) | 30 (disabled) |
| **Vault** | 100 (locked) | 60 (unlocked/exposed) |
| **Integrity** | 100 - 20 × alerts | 50 (no folders monitored) |
| **Network (NIDS)** | 100 - 10 × alerts | 40 (Suricata inactive) |
| **Password** | 90 (users registered) | 0 (no users in DB) |

---

**Q: Why is the score between 0 and 100?**

Because it is an intuitive percentage-like metric. 100 means perfectly secure,
0 means critically exposed. This makes it immediately understandable without
any security knowledge.

---

**Q: What causes the score to decrease?**

- Firewall disabled → firewall_score drops from 100 to **30**
- FIM alerts detected → -20 per alert (min 0)
- Suricata inactive → network_score drops to **40**
- Network alerts detected → -10 per alert (min 0)
- Vault unlocked → vault_score drops from 100 to **60**
- No users registered → password_score = **0**

---

**Q: What happens if the result becomes negative?**

Each component is protected with `max(0, ...)`:
```python
integrity_score = max(0, 100 - (20 * len(integrity_alerts)))
```
So no component can go below 0, and the overall score is always ≥ 0.

---

**Q: Why is an aggregated score useful?**

The user does not need to check 5 separate dashboards. A score below 70 is an
immediate signal that something needs attention. It also motivates the user to
fix issues — like a security health progress bar.

> **"Give me an example."**
>
> | Component | State | Score |
> |---|---|---|
> | Firewall | Disabled | 30 |
> | Vault | Locked | 100 |
> | Integrity | 2 alerts | 60 |
> | Network | Suricata off | 40 |
> | Password | Users registered | 90 |
>
> `Overall = (30 + 100 + 60 + 40 + 90) / 5 = 320 / 5 = **64**`

---

## 10. Logging System (5 Questions)

**File:** `backend/logger.py`
**Key function:** `log_event(level, message, operator)`

---

**Q: Why do you need audit logging?**

Security without logging is blind. If an attack happens, you need to know:
- Who logged in, when, from which IP
- What firewall rules were added or removed
- What files were changed
- What threats were detected and what actions were taken

Logs provide accountability and forensic evidence.

---

**Q: What information is stored in the logs?**

The `audit_logs` SQLite table stores:
- `timestamp` — exact UTC time of the event
- `level` — INFO / WARNING / ERROR
- `message` — human-readable description of what happened
- `operator` — which user triggered the event (if applicable)

Every `log_event()` call writes to **both** the text file and SQLite simultaneously.

---

**Q: Why use SQLite?**

SQLite is:
- A file-based database — no separate database server needed
- Built into Python (`import sqlite3`)
- Fast for read-heavy workloads
- The entire database is a single file: `database/logvigil.db`
- Allows SQL queries to filter, sort, and search logs from the web UI

---

**Q: Why store logs both in a file and database?**

- **`logvigil.log`** (text file) — human-readable, can be `tail -f`-ed in a terminal,
  survives even if SQLite gets corrupted, compatible with standard syslog tools
- **`audit_logs` SQLite table** — structured, queryable, supports filters
  (by operator, by level, by time range) from the LogVigil web interface

Both are written by the same `log_event()` function in `logger.py`.

---

**Q: How can administrators use these logs?**

- View events on the LogVigil Timeline page (reads from SQLite `audit_logs`)
- Filter by level (WARNING, ERROR) to find security events
- Filter by time range to investigate an incident
- Export to PDF via the Reports module
- Read `logvigil.log` directly with `tail -f logvigil.log` in a terminal

---

## 11. Backup & PDF Reports (4 Questions)

**File:** `backend/reports/router.py`, `backend/settings/router.py`

---

**Q: Why did you implement automated backups?**

Configuration data (firewall rules, FIM baselines, vault entries) is critical.
If the database is accidentally deleted or corrupted, all security settings are
lost. Automated backups ensure recovery is always possible.

---

**Q: What data is backed up?**

The SQLite database file (`database/logvigil.db`) contains all:
user accounts, password hashes, session tokens, firewall rules,
FIM baselines and alerts, audit logs, vault entries and encrypted keys,
threat recommendations.

---

**Q: Why generate PDF reports?**

PDF reports allow security information to be:
- Shared with managers or clients who don't have system access
- Archived for compliance requirements
- Printed for physical records
- Exported independent of the LogVigil application

---

**Q: How does the scheduler work?**

The `settings/router.py` module allows configuring automatic scheduled exports.
The backend uses a configurable interval to automatically generate and save
PDF reports and database backups at regular intervals without user intervention.

---

## 12. Security Architecture (7 Questions)

---

**Q: How are all modules connected?**

All modules are connected through:
1. **FastAPI** — the backend REST API server exposing endpoints for each module
2. **SQLite** (`logvigil.db`) — shared data store for all modules
3. **`logger.py`** — every module calls `log_event()` to write to the same log
4. **`security_service.py`** — shared security logic (Argon2id, lockouts, sessions)
5. **`db.py`** — shared database connection factory used by all modules

---

**Q: How does data flow through LogVigil?**

```
Browser (React frontend, port 5173)
      ↕ HTTP REST API
FastAPI Backend (port 8000)
      ├── auth/router.py          → users, sessions tables
      ├── vault/router.py         → vault_entries, vault_keys tables
      ├── integrity/router.py     → integrity_baselines, integrity_alerts
      ├── firewall/router.py      → firewall_rules, firewall_status tables
      ├── network/router.py       → reads /var/log/suricata/eve.json
      ├── alerts/router.py        → threat_recommendations table
      ├── phishing/router.py      → stateless (no DB writes)
      ├── security_score/router.py→ aggregates from all modules
      └── logger.py               → audit_logs table + logvigil.log
            ↕
      SQLite: database/logvigil.db
```

---

**Q: Which modules communicate with each other?**

| Module | Depends On |
|---|---|
| `alerts/router.py` (Threat Engine) | `network/router.py`, `firewall/router.py` |
| `security_score/router.py` | `firewall`, `vault`, `integrity`, `network` — all 4 |
| `auth/router.py` | `auth_service.py`, `security_service.py` |
| `vault/router.py` | `security_service.py` (Argon2id, lockout) |
| All modules | `logger.py`, `db.py` |

---

**Q: Where is the database used?**

Every module uses SQLite via `db.get_db()` from `backend/db.py`.
Key tables: `users`, `sessions`, `audit_logs`, `firewall_rules`,
`integrity_baselines`, `integrity_alerts`, `vault_entries`, `vault_keys`,
`login_attempts`, `vault_sessions`, `threat_recommendations`.

---

**Q: Where is encryption used?**

| Location | What is encrypted | Algorithm |
|---|---|---|
| `auth_service.py` | User passwords | PBKDF2-HMAC-SHA256 |
| `vault/router.py` | Master vault key (protected by PIN) | AES-256-GCM |
| `vault/router.py` | All vault data (files, credentials) | AES-256-GCM |
| `security_service.py` | Master Key hash (emergency recovery) | Argon2id |

---

**Q: Where is authentication applied?**

- Login → `auth/router.py` → `_validate_session()` checks every protected endpoint
- Vault → `vault/router.py` → requires valid session token + valid vault session
- All API endpoints that modify data require `Authorization: Bearer <token>` header

---

**Q: What happens from login → monitoring → threat detection → response → logging?**

```
1. User logs in → PBKDF2 verifies password → session token created (auth/router.py)
2. Dashboard loads → all modules polled via React frontend
3. FIM scans folders → compute_sha256() → compare to baselines (integrity/router.py)
4. Suricata runs → writes alerts to eve.json (external process)
5. LogVigil reads eve.json → get_network_alerts() (network/router.py)
6. Threat Engine → sync_threat_recommendations() analyzes alerts (alerts/router.py)
7. Security Score recalculated → get_security_score() averages all 5 components
8. User approves BLOCK_IP → run_firewall_command() → ufw deny from <IP>
9. Every step → log_event() → logvigil.log + audit_logs SQLite table
```

---

## 13. "Show Me Where You Implemented It" (Know These Cold)

> Your teacher may skip all theory and ask: *"Show me where PBKDF2 is."*
> Point to the exact file and function immediately.

---

| Feature | File | Function |
|---|---|---|
| PBKDF2 password hash | `backend/auth_service.py` | `hash_password()` |
| Salt generation | `backend/auth_service.py` | `os.urandom(16)` inside `hash_password()` |
| Brute-force lockout | `backend/security_service.py` | `check_login_lockout()` — `LOGIN_MAX_ATTEMPTS = 5`, `LOGIN_LOCKOUT_SECONDS = 900` |
| Session token creation | `backend/auth/router.py` | `_create_session()` — `secrets.token_hex(32)` |
| Argon2id (master key) | `backend/security_service.py` | `hash_master_key()`, `_ph = PasswordHasher(...)` |
| Vault key derivation (PIN→key) | `backend/vault/router.py` | `derive_key()` — PBKDF2HMAC |
| AES-256-GCM encryption | `backend/vault/router.py` | `encrypt_vault_key()` — `AESGCM(derivation_key)` |
| SHA-256 file hashing | `backend/integrity/router.py` | `compute_sha256()` |
| 64 KB chunk processing | `backend/integrity/router.py` | `f.read(65536)` inside `compute_sha256()` |
| Firewall shell commands | `backend/firewall/router.py` | `run_firewall_command()` — `subprocess.run()` |
| UFW vs iptables detection | `backend/firewall/router.py` | `get_firewall_backend()` — `shutil.which()` |
| Suricata status check | `backend/network/router.py` | `check_suricata_service_active()` |
| eve.json path | `backend/network/router.py` | `EVE_JSON_PATH = "/var/log/suricata/eve.json"` |
| Threat classification | `backend/alerts/router.py` | `sync_threat_recommendations()` |
| Phishing score | `backend/phishing/router.py` | `analyze_url()` |
| @ spoofing detection | `backend/phishing/router.py` | `at_sign_in_url = "@" in raw_host` |
| Security score formula | `backend/security_score/router.py` | `get_security_score()` — average of 5 components |
| Dual logging (file + DB) | `backend/logger.py` | `log_event()` |
| Database schema | `backend/db.py` | `init_db()` |

---

## 🔥 Top 20 Questions to Memorise First

If you have limited time, master these in order:

1. What is LogVigil and what problem does it solve?
2. Explain the complete system architecture (use the data flow diagram above)
3. How does authentication work? (PBKDF2 → salt → hash → session token)
4. Why PBKDF2? Why SHA-256? What is a salt?
5. What is brute-force protection? (5 attempts → 15 min lockout — `security_service.py`)
6. How does the vault work? (PIN → PBKDF2 → PIN key → decrypt master key → AES-GCM data)
7. What is AES-256-GCM and why? (256-bit key + authenticated encryption)
8. What is envelope encryption?
9. What is Argon2id and why for the master key? (memory-hard, GPU-resistant)
10. How does FIM work? (SHA-256 → baseline → compare → MODIFIED/ADDED/DELETED)
11. Why 64 KB chunks? (memory efficiency for large files)
12. What is Suricata and what is NIDS?
13. What is eve.json? (Suricata's output at `/var/log/suricata/eve.json`)
14. Explain the complete attack flow (traffic → Suricata → eve.json → Threat Engine → firewall)
15. How does the Threat Engine respond? (keyword matching → BLOCK_IP / FIREWALL_ENABLE)
16. What is phishing? Typosquatting? @ spoofing?
17. How does the phishing score work? (100 - penalties for each red flag found)
18. How is the Security Score calculated? (average of 5 component scores)
19. Why log to both a file and SQLite? (file = human-readable, SQLite = queryable)
20. For any feature the teacher mentions: know the file name + function name immediately

---

## 🎯 Answer Template — Use for Every Feature

```
What?     → What does this feature do?
Why?      → Why was it needed / why this approach?
How?      → How does it work technically?
Where?    → Which file and function?
Input?    → What data goes in?
Output?   → What comes out?
Benefit?  → What security problem does it solve?
```

**FIM example:**
- **What?** Detects unauthorized changes to files
- **Why?** To protect important system/config files from tampering
- **How?** SHA-256 hashes files in 64 KB chunks, compares to stored baseline
- **Where?** `backend/integrity/router.py` → `compute_sha256()`, `walk_folder()`
- **Input?** File path / monitored directory
- **Output?** `MODIFIED` / `ADDED` / `DELETED` stored in `integrity_alerts`
- **Benefit?** Detects malware that modifies system files, rootkits, unauthorized config changes

**PBKDF2 example:**
- **What?** Converts a user password into a secure stored hash
- **Why?** Plain-text and single-hash passwords are trivial to crack
- **How?** Runs SHA-256 100,000 times on password + random 16-byte salt
- **Where?** `backend/auth_service.py` → `hash_password()`
- **Input?** Plain-text password string
- **Output?** 64-character hex hash + 32-character hex salt (stored in `users` table)
- **Benefit?** Makes cracking one password take minutes to hours instead of milliseconds

---

*Good luck — you've got this!*
