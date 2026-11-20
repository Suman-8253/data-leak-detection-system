# Data Leak Detection & SQL Injection Prevention System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.0-green.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-336791.svg)](https://www.postgresql.org/)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM-red.svg)](https://cryptography.io/)
[![Argon2id](https://img.shields.io/badge/Password%20Hash-Argon2id-orange.svg)](https://argon2-cffi.readthedocs.io/)
[![Security](https://img.shields.io/badge/Defense--in--Depth-Active-brightgreen.svg)]()

An enterprise-grade cybersecurity demonstration application implementing **defense-in-depth architecture** to protect sensitive corporate assets against SQL injection (SQLi), data exfiltration, unauthorized access, and credential compromise.

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                            Client / Browser                             |
+-------------------------------------------------------------------------+
                                    |
                    [HTTPS / CSRF Protection / Rate Limiting]
                                    v
+-------------------------------------------------------------------------+
|                         Flask Application Layer                         |
|   * Role-Based Access Control (RBAC: Admin / User)                      |
|   * Scoped Capability Token Verification                                |
|   * Strict Input Validation & Normalization                             |
+-------------------------------------------------------------------------+
          |                                              |
          v                                              v
+-----------------------+                      +--------------------------+
|  Heuristic Detection  |                      |  Cryptographic Engine    |
|  * Regex SQLi Auditing|                      |  * AES-256-GCM (Payload) |
|  * Real-Time Telemetry|                      |  * Argon2id (Passwords)  |
+-----------------------+                      +--------------------------+
          |                                              |
          +----------------------+-----------------------+
                                 |
                                 v
+-------------------------------------------------------------------------+
|                  Parameterized Data Access Layer                        |
|   * Strict %s Parameter Binding (Zero string concatenation)             |
|   * Thread-Safe PostgreSQL Connection Pool                              |
+-------------------------------------------------------------------------+
                                 |
                                 v
+-------------------------------------------------------------------------+
|                       PostgreSQL 16 Database                            |
|   * users (Argon2id hashes)                  * secure_records (AES-GCM) |
|   * security_events (Intrusion telemetry)    * capability_codes (SHA256)|
|   * audit_logs (Immutable audit trail)                                 |
+-------------------------------------------------------------------------+
```

---

## Core Security Features

### 1. SQL Injection Prevention & Heuristic Auditing
* **Zero-Trust Parameterization**: All database interactions use strictly parameterized SQL queries via `psycopg2`. User inputs are bound as values, never interpreted as code, completely preventing SQL injection.
* **Passive Intrusion Detection**: Regex-based heuristic filters analyze inputs for classic signatures (`' OR '1'='1`, `UNION SELECT`, `; DROP TABLE;`, `SLEEP()`, stacked queries) and record structured alerts without compromising query safety.
* **Interactive SQLi Defense Lab**: Built-in interactive test suite demonstrating attack attempts vs. parameterized protection in real-time.

### 2. Authenticated Data-at-Rest Encryption
* **AES-256-GCM (Galois/Counter Mode)**: Confidential record contents are encrypted prior to database insertion.
* **Unique Initialization Vectors**: A distinct 12-byte random nonce is generated for every encrypted payload.
* **Tamper-Proof Integrity**: GCM authentication tags guarantee that unauthorized database modifications cause decryption to fail safely.

### 3. State-of-the-Art Password Hashing
* Uses **Argon2id** (winner of the Password Hashing Competition) with 64 MB memory cost, 3 iterations, and 4 parallel threads.
* Passwords are never stored in plaintext or reversible encryption.

### 4. Scoped Capability-Based Access Control
* Generates time-bounded, fine-grained capability tokens (`secrets.token_urlsafe(48)`).
* Only SHA-256 hashes are stored in the database.
* Granular permissions (`READ_OWN_RECORD`, `CREATE_RECORD`, `MANAGE_USERS`) with instant revocation capability.

### 5. Auditing & Threat Monitoring
* **Immutable Audit Trail**: Every sensitive operation (login, record view, token grant, admin role modification) is recorded with correlation IDs.
* **Sanitized Logging**: Automatically redacts credentials and masks sensitive payloads from logs.

---

## Project Structure

```
├── app.py                      # Flask application factory, error handlers & security headers
├── config.py                   # Configuration environments (Dev, Prod, Test)
├── requirements.txt            # Python dependencies
├── .env.example                # Template configuration file
├── backend/                    # Modular Flask Blueprints
│   ├── auth_routes.py          # /login, /register, /logout
│   ├── record_routes.py        # /records (CRUD for encrypted records)
│   ├── security_routes.py      # /security-monitor, /sql-injection-demo
│   ├── admin_routes.py         # /admin/users, /admin/audit-logs, /admin/dashboard
│   ├── capability_routes.py    # /capabilities (Token generation & revocation)
│   └── user_routes.py          # /dashboard, /settings
├── database/                   # Data Access Layer
│   ├── schema.sql              # DDL Schema definitions
│   ├── connection.py           # Thread-safe PostgreSQL connection pool
│   └── repositories.py         # Parameterized DAO layer
├── security/                   # Core Security Subsystems
│   ├── encryption.py           # AES-256-GCM cipher routines
│   ├── password_security.py    # Argon2id hashing & verification
│   ├── capability_codes.py     # Token generation & verification
│   ├── sql_safety.py           # SQLi pattern matching & log sanitization
│   └── rate_limiting.py        # Anti-brute force limiter
├── frontend/                   # UI Layer
│   └── templates/              # Responsive Bootstrap 5 cybersecurity templates
└── scripts/                    # Bootstrap utilities
    ├── generate_encryption_key.py
    ├── initialize_database.py
    └── create_admin.py
```

---

## Quickstart Guide

### Prerequisites
* Python 3.10+
* PostgreSQL 14+

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/data-leak-detection-system.git
cd data-leak-detection-system/data_leak_detection
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Configure Environment
Copy `.env.example` to `.env` and fill in your database credentials:
```bash
cp .env.example .env
```
Generate an AES-256 encryption key:
```bash
python scripts/generate_encryption_key.py
```

### 4. Initialize Database & Admin User
```bash
python scripts/initialize_database.py
python scripts/create_admin.py
```

### 5. Run the Application
```bash
python app.py
```
Open your browser at **http://localhost:5000**.

Default Bootstrap Admin Credentials:
* **Username**: `admin`
* **Password**: `Admin@12345`

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
