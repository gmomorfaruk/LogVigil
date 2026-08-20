# 🛡️ LogVigil: LogVigil — Linux Security Monitor & Log Analyzer

> A comprehensive desktop security platform built with **FastAPI**, **React**, and **SQLite**. LogVigil provides file encryption, password management, firewall control, network monitoring, phishing detection, and threat analysis in a unified cyber-themed interface.

---

## ✨ Features

| Module | Description |
|:---|:---|
| **Authentication** | PBKDF2-HMAC-SHA256 login with DB-persisted sessions |
| **Vault** | AES-256-GCM file encryption/decryption with per-user PIN |
| **Password Vault** | Encrypted credential storage with AES-256-GCM |
| **File Integrity** | Real SHA256 baseline hashing & change detection |
| **Firewall Manager** | Control system firewall (ufw/iptables) from the UI |
| **Network Monitor** | Suricata IDS integration with eve.json parsing |
| **Threat Engine** | Automated alert analysis with countermeasure recommendations |
| **Phishing Protection** | URL analysis for HTTPS, blacklists, typosquatting, IP URLs |
| **Security Score** | Weighted composite score from all modules |
| **Timeline** | Chronological event feed aggregating all audit logs |
| **Reports** | PDF report generation with system security summary |
| **Settings** | Database backup/restore, dark mode, notifications |

---

## 🛠️ Tech Stack

- **Backend:** Python 3 + [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
- **Frontend:** [React 19](https://react.dev/) + [Vite 8](https://vitejs.dev/)
- **Database:** SQLite3
- **Cryptography:** `cryptography` library (AES-256-GCM, PBKDF2)
- **System Integration:** `ufw` / `iptables`, `systemctl` (Suricata)

---

## 📁 Project Structure

```
SecureVault/
├── backend/
│   ├── auth/            # Authentication router
│   ├── vault/           # File encryption & password vault
│   ├── firewall/        # System firewall management
│   ├── integrity/       # SHA256 file integrity monitoring
│   ├── network/         # Suricata network monitor
│   ├── phishing/        # URL phishing analysis
│   ├── alerts/          # Threat engine & recommendations
│   ├── reports/         # PDF report generation
│   ├── security_score/  # Composite security scoring
│   ├── timeline/        # Event timeline aggregation
│   ├── settings/        # App settings, backup/restore
│   ├── main.py          # FastAPI app entry point
│   ├── db.py            # SQLite schema & connection
│   ├── logger.py        # Audit logging (file + DB)
│   ├── auth_service.py  # Password hashing utilities
│   └── requirements.txt # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/  # Sidebar navigation
│   │   ├── pages/       # All dashboard pages
│   │   ├── App.jsx      # Main app with auth & routing
│   │   └── App.css      # Cyber-themed styling
│   ├── package.json     # Node dependencies
│   └── vite.config.js   # Vite configuration
├── database/
│   └── securevault.db   # SQLite database file
├── tests/
│   ├── test_auth.py     # Authentication tests
│   ├── test_mock_api.py # API endpoint tests
│   └── benchmark.py     # Performance benchmarks
├── docs/                # Architecture, API & Threat Model docs
│   ├── architecture.md  # System diagrams & database ERD
│   ├── api_reference.md # Complete REST API documentation
│   └── threat_model.md  # Security analysis & threat matrix
└── project_plan.md      # Development roadmap
```

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

The API will be available at `http://localhost:8000`. Visit `http://localhost:8000/docs` for the interactive OpenAPI documentation.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The UI will be available at `http://localhost:5173`.

### Desktop App (Tauri)

To launch SecureVault as a native desktop application:

```bash
cd frontend
npm run desktop        # Development desktop mode
npm run desktop:build  # Compile native installer/binary
```

### First-Time Usage

1. Start the backend server (`uvicorn`)
2. Start the frontend dev server (`npm run dev`)
3. Open `http://localhost:5173` in your browser
4. Click **Register Key** to create an operator account
5. Login with your credentials
6. Navigate to the **Vault** tab and set up your personal vault PIN

---

## 🔐 Security Architecture

- **Passwords** are hashed with PBKDF2-HMAC-SHA256 (100,000 iterations) before storage
- **Vault encryption** uses AES-256-GCM with per-user PBKDF2-derived keys
- **Sessions** are persisted in the database with 24-hour auto-expiry
- **Vault PINs** are stored as salted PBKDF2 hashes with unique per-user vault salts
- **File integrity** baselines use SHA256 checksums with chunk-based processing

---

## 🧪 Running Tests

```bash
cd tests
pytest test_auth.py -v
pytest test_mock_api.py -v
python benchmark.py
```

---

## 📄 License

This project is for educational and personal use.
# LogVigil
