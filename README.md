# VenueDesk Agent

Autonomous, cryptographic endpoint identity and inventory management system for campus hardware infrastructure.

## Architecture Overview

VenueDesk Agent is structured as a high-security monorepo:
- `venuedesk-backend/`: Flask 3 control plane with Ed25519 authentication, hardware reconciliation, audit logs, and telemetry ingestion.
- `venuedesk-agent/`: Lightweight, resilient cross-platform endpoint agent with local SQLite outbox and hardware collectors.
- `tools/`: Fleet simulators and test fixtures for end-to-end integration testing.
- `docs/`: Technical specifications, architectural decision records, runbooks, and threat model.

## Quickstart (Development)

### 1. Prerequisites
- Python 3.11+
- Virtual environment tool

### 2. Setup

```bash
# Clone the repository
git clone https://github.com/Amandeep-winner/VenueDesk-Agent.git
cd VenueDesk-Agent

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install editable packages with dev dependencies
pip install -e "./venuedesk-backend[dev]" -e "./venuedesk-agent[dev]"
```

### 3. Run Tests

```bash
pytest -q
```

## Security Model

- Device authentication uses asymmetric Ed25519 signatures over canonical request strings.
- Raw pairing tokens are single-use, short-lived, stored hashed (SHA-256), and never logged.
- Hardware fingerprints use versioned canonical serialization with HMAC-SHA256 hashed anchors.
- High similarity scores never automatically grant asset pairing authority.
