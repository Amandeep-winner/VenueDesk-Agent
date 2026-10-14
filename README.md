# VenueDesk Endpoint Agent & Control Plane

[![CI Status](https://github.com/Amandeep-winner/VenueDesk-Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Amandeep-winner/VenueDesk-Agent/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests: 235 Passed](https://img.shields.io/badge/tests-235%20passed-success.svg)](docs/HARDENING_REPORT.md)

Autonomous, cryptographic endpoint identity, hardware reconciliation, and telemetry management system for campus and enterprise IT infrastructure.

---

## 1. Overview

VenueDesk is an enterprise hardware management control plane and cross-platform endpoint agent designed for computer laboratories, universities, and distributed workstations.
Physical computers in institutional environments frequently undergo component swaps, operating system reinstalls, dual-boot repartitioning, and offline network disconnects.
Standard inventory systems rely on mutable software properties like hostnames or MAC addresses that easily cause duplicate records, mismatched asset tags, and phantom endpoints.

VenueDesk solves this challenge through an identity model anchored in:
- **Asymmetric Cryptography:** Every endpoint generates local Ed25519 private keys that never leave the host.
- **Hardware Anchor Reconciliation:** Versioned fingerprints use HMAC-SHA256 digests over immutable motherboard and chassis identifiers.
- **Database-Level Invariants:** Partial unique SQL indexes guarantee that an asset can only ever be actively linked to exactly one physical device at a time.
- **Offline Tolerance:** A SQLite WAL outbox buffers telemetry and events during outages, draining in strict priority order upon reconnection with zero duplicate server-side processing.

---

## 2. Architecture & Monorepo Structure

VenueDesk is structured as a hardened monorepo containing the backend control plane, endpoint agent, deployment tooling, and architectural documentation.

```
VenueDesk-Agent/
├── venuedesk-backend/             # Flask 3 Control Plane Backend
│   ├── app/
│   │   ├── api/                   # REST API routes and admin UI views
│   │   ├── models/                # SQLAlchemy ORM models and audit listeners
│   │   ├── security/              # Ed25519 signatures, RBAC, CSRF, policy, replay defense
│   │   ├── services/              # Identity reconciliation, enrollment, telemetry, jobs
│   │   ├── templates/             # Server-rendered administrative dashboard (Bootstrap 5)
│   │   └── cli.py                 # Flask CLI commands (seeding, pruning, maintenance)
│   ├── migrations/                # Alembic schema versioning scripts (empty -> head)
│   ├── gunicorn.conf.py           # Production WSGI server configuration
│   └── Dockerfile                 # Hardened container image with unprivileged user
│
├── venuedesk-agent/               # Cross-Platform Endpoint Daemon
│   ├── agent/
│   │   ├── collectors/            # Hardware evidence, GPU, storage, process, network collectors
│   │   ├── communication/         # Authenticated HTTP client, retries, heartbeat, enrollment
│   │   ├── identity/              # Fingerprinting, evidence serialization, Ed25519 key store
│   │   ├── jobs/                  # Allowlisted remote job execution and diagnostics
│   │   ├── storage/               # SQLite WAL outbox with priority shedding and crash recovery
│   │   ├── update.py              # Safe update verification with Ed25519 release signature
│   │   └── main.py                # Agent CLI (run, enroll, status, recover, rotate-credential)
│   └── installers/                # Platform installation scripts and service wrappers
│
├── deploy/                        # Production deployment manifests
│   └── nginx/                     # TLS termination and reverse proxy configuration
│
├── docs/                          # Comprehensive technical documentation
│   ├── API.md                     # REST API reference and endpoint policies
│   ├── ARCHITECTURE.md            # System architecture and data flow specifications
│   ├── DECISIONS.md               # Architecture Decision Records (ADRs) for Phases 0-8
│   ├── HARDENING_REPORT.md        # Comprehensive hardening verification report
│   ├── PILOT_PLAN.md              # 5-10 machine lab pilot plan and verification gates
│   ├── PRD.md                     # Product Requirements Document
│   ├── RUNBOOK.md                 # Operations manual, backup procedures, disaster recovery
│   ├── THREAT_MODEL.md            # Security threat model and mitigation strategies
│   └── TRD.md                     # Technical Requirements Document
│
├── installers/                    # Standalone system installers for Linux and Windows
├── tests/                         # Shared integration fixtures and end-to-end test suites
├── tools/                         # Operational verification and migration diagnostic tools
└── docker-compose.yml             # Local production deployment (Postgres, Backend, Nginx)
```

### High-Level Data Flow

```mermaid
flowchart TD
    subgraph Workstation["Physical Workstation"]
        Agent["VenueDesk Agent Daemon"]
        KeyStore["Ed25519 Key Store (0700 / ACLs)"]
        Outbox[("Local SQLite WAL Outbox")]
        Collectors["Hardware Evidence Collectors"]
        
        Collectors --> Agent
        KeyStore <--> Agent
        Agent <--> Outbox
    end

    subgraph Network["Network Boundary"]
        ReverseProxy["Nginx TLS Reverse Proxy (:443)"]
    end

    subgraph ControlPlane["VenueDesk Control Plane"]
        Backend["Flask Backend (Gunicorn Sync Workers)"]
        Policy["Security Pipeline & Policy Enforcement"]
        Reconciliation["Identity Reconciliation Engine"]
        Postgres[("PostgreSQL 16 Database")]
        
        Backend --> Policy
        Policy --> Reconciliation
        Reconciliation --> Postgres
    end

    Agent -- "HTTPS + Ed25519 Signatures" --> ReverseProxy
    ReverseProxy --> Backend
```

---

## 3. Core Features

### 3.1 Cryptographic Authentication & Proof of Possession
- Every request from an endpoint is signed using its local private Ed25519 key over a canonical payload string (`METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256`).
- Request timestamps must fall within an acceptable clock skew window (default 120 seconds).
- Replay attacks are mitigated by single-statement atomic insertion into `request_nonces`.
- Route policies in `app/security/policy.py` enforce state-based access control, failing closed for unregistered routes.

### 3.2 Single-Point Device-to-Asset Mapping
- Mapping an institutional asset to an endpoint is strictly governed by `pair_device` in `app/services/identity_service.py`.
- Row-level database locks (`with_for_update()`) serialize concurrent enrollment requests.
- Database partial unique indexes (`uq_active_link_per_asset` and `uq_active_link_per_device`) enforce that neither an asset nor a device can have more than one `ACTIVE` link.
- Reassigning an asset atomically closes previous links with immutable audit records.

### 3.3 Tri-State Identity Reconciliation & Append-Only History
- Hardware fingerprints v1 use SHA-256 digests over sorted, normalized anchor tables (motherboard UUID, chassis serial, CPU model, BIOS release).
- Reconciliation uses tri-state comparison logic (`MATCH`, `MISMATCH`, `UNKNOWN`).
- Missing hardware attributes (`None == None`) evaluate to `UNKNOWN` and never contribute to a match.
- Hardware component swaps (e.g. GPU replacement, RAM upgrades) produce append-only `HardwareChangeRecord` rows and transition endpoints to `PENDING_REVERIFICATION`.

### 3.4 Multi-OS Isolation & Dual-Boot Support
- Workstations running dual-boot environments generate distinct `os_installation_id` UUIDs for each operating system.
- Sibling OS installations share a single `physical_devices` record linked to the institutional asset.
- Secondary OS installations enroll using device-scoped tokens (`TokenScope.DEVICE`) without creating duplicate device entities.
- Recovery approvals isolate the affected OS slot, marking reinstalled credentials historical while preserving sibling OS credentials.

### 3.5 Durable Offline Outbox & Server Idempotency
- When an endpoint is disconnected, outbound telemetry and events persist in a SQLite WAL outbox.
- Stale `IN_FLIGHT` messages older than 60 seconds automatically revert to `PENDING` on startup after process crashes.
- Under buffer pressure, lowest-priority telemetry is shed first, ensuring priority-0 identity events are never dropped before TTL expiration.
- Server-side idempotency tracks processed event IDs in `processed_events`, acknowledging duplicates without duplicate processing.

### 3.6 Administrator Web Dashboard
- Server-rendered HTML dashboard built with Bootstrap 5 and Chart.js.
- Role-Based Access Control (`infra_admin` for mutations, `infra_viewer` for read-only access).
- CSRF protection across all mutating forms.
- High-impact lifecycle actions (Suspend, Unsuspend, Retire, Rotate Credential, Revoke, Reassign) require typed confirmation and reason logging.
- Eager-loaded queries prevent N+1 performance degradations.

---

## 4. Quickstart (Development)

### Prerequisites
- Python 3.11 or higher
- Git
- Virtual environment support (`venv`)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Amandeep-winner/VenueDesk-Agent.git
cd VenueDesk-Agent

# 2. Create and activate a Python virtual environment
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# 3. Install packages in editable mode with development dependencies
pip install --upgrade pip
pip install -e "./venuedesk-backend[dev]" -e "./venuedesk-agent[dev]"
```

### Database Initialization & Demo Seeding

```bash
# Run database migrations to head
flask --app venuedesk-backend/app:create_app db upgrade --directory venuedesk-backend/migrations

# Seed demo assets and default administrator (admin / admin123)
flask --app venuedesk-backend/app:create_app seed-demo
```

### Launching the Development Server

```bash
# Start backend control plane on port 5001
flask --app venuedesk-backend/app:create_app run --port 5001 --debug
```

Access the administrative dashboard in your browser at:
`http://127.0.0.1:5001/admin/infrastructure/login`

---

## 5. Production Deployment

### Docker Compose Deployment

VenueDesk includes a production Docker Compose configuration deploying PostgreSQL 16, the Gunicorn-backed Flask backend, and an optional Nginx TLS reverse proxy.

```bash
# Configure production secrets in your environment
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export DEPLOYMENT_SALT="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Launch backend and PostgreSQL services
docker compose up -d

# Check service health
docker compose ps
curl -f http://127.0.0.1:5001/healthz
```

### Production Configuration Requirements

In production mode (`FLASK_ENV=production`), the application refuses to start unless the following environment variables are explicitly defined:

| Environment Variable | Description | Requirement |
|---|---|---|
| `SECRET_KEY` | Flask session and cryptographic signing key | Strong random string (minimum 32 characters) |
| `DEPLOYMENT_SALT` | Organization-specific anchor hashing salt | Dedicated secret string (minimum 32 characters) |
| `DATABASE_URL` | PostgreSQL connection URL | Must target PostgreSQL (SQLite refused unless `ALLOW_SQLITE_PROD=true`) |
| `PORT` | WSGI server listening port | Defaults to `5001` |
| `PROXYFIX_ENABLED` | Trust proxy headers (`X-Forwarded-Proto`, `X-Forwarded-For`) | Set to `true` behind Nginx/Caddy |
| `HSTS_ENABLED` | Enforce HTTP Strict Transport Security | Set to `true` |

---

## 6. Endpoint Agent Installation

### Linux Workstations (systemd)

The Linux installer creates a dedicated unprivileged `venuedesk` system user and sandboxes the service using systemd security flags (`ProtectSystem=strict`, `NoNewPrivileges=true`).

```bash
# Run installer as root
sudo ./installers/linux/install.sh --server https://control.venue.internal --token PAIR-XXXXXXXXXXXX

# Verify service status
systemctl status venuedesk-agent.service
journalctl -u venuedesk-agent.service -f
```

To cleanly uninstall the agent:

```bash
# Remove service and application binaries
sudo ./installers/linux/uninstall.sh

# To purge configuration, keys, and local state:
sudo ./installers/linux/uninstall.sh --purge
```

### Windows Workstations (PowerShell)

The Windows installer configures restrictive NTFS access control lists on `C:\ProgramData\VenueDesk` allowing access only to `SYSTEM` and `BUILTIN\Administrators`.

```powershell
# Run PowerShell installer as Administrator
powershell.exe -ExecutionPolicy Bypass -File .\installers\windows\install.ps1 -ServerUrl https://control.venue.internal -Token PAIR-XXXXXXXXXXXX
```

To cleanly uninstall on Windows:

```powershell
# Stop and unregister Windows Service
powershell.exe -ExecutionPolicy Bypass -File .\installers\windows\uninstall.ps1

# To purge local state directory:
powershell.exe -ExecutionPolicy Bypass -File .\installers\windows\uninstall.ps1 -Purge
```

### Agent CLI Commands

The agent executable provides operational inspection and recovery commands:

```bash
# Inspect agent health, enrollment status, and queue depth
venuedesk-agent status

# Print local identity evidence hashes without exposing private keys
venuedesk-agent print-identity

# Run a single inventory and telemetry collection cycle
venuedesk-agent collect-once

# Trigger OS recovery workflow after disk reimaging
venuedesk-agent recover --server https://control.venue.internal --wait

# Request Ed25519 credential rotation
venuedesk-agent rotate-credential
```

---

## 7. Operational Runbook & Maintenance

### Database Maintenance & Retention CLI

To maintain database performance, execute scheduled cleanup commands via the Flask CLI:

```bash
# Purge high-frequency telemetry samples older than N days
flask --app venuedesk-backend/app:create_app purge-telemetry --older-than-days 30

# Purge expired request nonces
flask --app venuedesk-backend/app:create_app purge-nonces

# Purge processed idempotency event records older than N days
flask --app venuedesk-backend/app:create_app purge-processed-events --older-than-days 2
```

### Migration Verification on Database Copy

Before applying migrations in production, verify schema upgrades and constraint integrity on a copy of your database:

```bash
python tools/test_migration_on_copy.py
```

### Database Backup & Disaster Recovery

Perform verified database backups using PostgreSQL native tools:

```bash
# Create custom-format PostgreSQL backup
pg_dump --format=custom --no-owner --no-privileges --dbname="${DATABASE_URL}" --file="/var/backups/venuedesk.dump"

# Restore into fresh database
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="${DATABASE_URL}" /var/backups/venuedesk.dump

# Execute automated backup/restore verification script
bash tools/backup_restore_check.sh
```

---

## 8. Testing & Quality Assurance

The repository enforces strict code quality and comprehensive test coverage across unit, integration, and end-to-end suites.

```bash
# Run full automated test suite on SQLite
pytest -q -m "not postgres"

# Run PostgreSQL-specific concurrency tests (requires running PostgreSQL instance)
TEST_DATABASE_URL="postgresql://user:pass@localhost:5432/venuedesk_test" pytest -q -m postgres

# Run Ruff linter and code formatting verification
ruff check .
ruff format --check .

# Dump route policies to verify all endpoints are explicitly registered
python tools/dump_routes.py
```

### Continuous Integration (CI)

GitHub Actions runs automated test matrices on every pull request and push to main branches:
- **Lint & Format:** Ruff linter and formatting checks.
- **Backend Unit & Integration:** SQLite test execution on Ubuntu.
- **PostgreSQL Service Container:** PostgreSQL 16 concurrency and transaction isolation tests.
- **Cross-Platform Agent:** Agent test suite executing on both Ubuntu and Windows runners.
- **End-to-End Workflows:** Full lifecycle enrollment, pairing, dual-boot, and offline tests.
- **Security Scanners:** Bandit code scanning and dependency audits.

---

## 9. Documentation Directory

Detailed specifications, runbooks, and architectural records are located in the [docs/](docs/) directory:

- [docs/API.md](docs/API.md): Complete REST API documentation and authorization policies.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): System architecture, identity models, and security boundaries.
- [docs/DECISIONS.md](docs/DECISIONS.md): Architecture Decision Records (ADRs) across all implementation phases.
- [docs/HARDENING_REPORT.md](docs/HARDENING_REPORT.md): Complete hardening verification results and test counts.
- [docs/PILOT_PLAN.md](docs/PILOT_PLAN.md): 5-10 machine lab deployment plan and go/no-go gates.
- [docs/PRD.md](docs/PRD.md): Product Requirements Document.
- [docs/RUNBOOK.md](docs/RUNBOOK.md): System operations manual, disaster recovery, and troubleshooting.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): Threat modeling analysis and mitigations.
- [docs/TRD.md](docs/TRD.md): Technical Requirements Document.
- [tools/pilot_checklist.md](tools/pilot_checklist.md): Step-by-step pilot rollout checklist.

---

## 10. License

VenueDesk is licensed under the [MIT License](LICENSE).
