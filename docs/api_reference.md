# SecureVault API Reference

Base URL: `http://localhost:8000`

Interactive documentation: `http://localhost:8000/docs`

---

## Authentication

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/auth/register` | Register a new operator |
| `POST` | `/api/auth/login` | Login and receive session token |
| `POST` | `/api/auth/logout` | Terminate session (requires `Authorization` header) |
| `GET` | `/api/auth/me` | Validate current session |

### Register
```json
POST /api/auth/register
Body: { "username": "operator", "password": "mypassword" }
Response: { "message": "Registration successful" }
```

### Login
```json
POST /api/auth/login
Body: { "username": "operator", "password": "mypassword" }
Response: { "message": "Login successful", "token": "abc123...", "username": "operator" }
```

---

## Vault

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/vault/status` | Get vault lock state & PIN status |
| `POST` | `/api/vault/setup-pin` | First-time PIN configuration |
| `POST` | `/api/vault/toggle` | Lock/unlock vault with PIN |
| `GET` | `/api/vault/files` | List encrypted files (vault must be unlocked) |
| `POST` | `/api/vault/encrypt` | Encrypt a file |
| `POST` | `/api/vault/decrypt` | Decrypt a file |
| `GET` | `/api/vault/passwords` | List stored credentials |
| `POST` | `/api/vault/passwords` | Store new credential |
| `DELETE` | `/api/vault/passwords/{id}` | Delete a credential |

---

## File Integrity

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/integrity/status` | Monitored folders, file counts, alert counts |
| `POST` | `/api/integrity/monitor` | Add a folder to monitor (baselines all files) |
| `DELETE` | `/api/integrity/monitor` | Remove a monitored folder |
| `POST` | `/api/integrity/scan` | Scan all baselines for changes |
| `GET` | `/api/integrity/alerts` | List integrity alerts |
| `DELETE` | `/api/integrity/alerts` | Clear all alerts |

---

## Firewall

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/firewall/status` | Get firewall enabled state |
| `POST` | `/api/firewall/toggle` | Enable/disable firewall |
| `GET` | `/api/firewall/rules` | List firewall rules |
| `POST` | `/api/firewall/rules` | Create a firewall rule |
| `DELETE` | `/api/firewall/rules/{rule_id}` | Delete a firewall rule |

---

## Network Monitor

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/network/status` | Get Suricata monitor status |
| `POST` | `/api/network/toggle` | Start/stop Suricata service |
| `GET` | `/api/network/alerts` | List network alerts (from eve.json) |

---

## Threat Engine

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/alerts/summary` | Risk summary with active threat count |
| `GET` | `/api/alerts/recommendations` | List threat recommendations |
| `POST` | `/api/alerts/recommendations/{id}/apply` | Apply a countermeasure |

---

## Phishing Protection

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/phishing/analyze` | Analyze a URL for phishing risk |

---

## Security Score

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/security-score` | Composite score with 5-component breakdown |

---

## Timeline

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/timeline` | Chronological event feed |

---

## Reports

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/reports/list` | List generated reports |
| `POST` | `/api/reports/generate` | Generate a new report |
| `GET` | `/api/reports/download/{id}` | Download report as PDF |

---

## Settings

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/settings` | Get current settings |
| `POST` | `/api/settings` | Update settings |
| `POST` | `/api/settings/backup` | Backup database |
| `POST` | `/api/settings/restore` | Restore database from backup |

---

## Logs

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/logs` | Get all audit log entries |

---

## Common Status Codes

| Code | Meaning |
|:---|:---|
| `200` | Success |
| `201` | Created |
| `400` | Bad request / validation error |
| `401` | Unauthorized / invalid credentials |
| `403` | Forbidden (vault locked) |
| `404` | Resource not found |
| `500` | Internal server error |
