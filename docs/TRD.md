# VenueDesk Technical Requirements Document (TRD)

## 1. Document Overview and System Scope

This Technical Requirements Document (TRD) details the architectural, cryptographic, algorithmic, and engineering specifications for the VenueDesk Agent and Control Plane monorepo.
The system provides reliable IT asset mapping, physical device tracking, cryptographic endpoint management, and telemetry ingestion for institutional desktop fleets.
This document serves as the authoritative technical reference for engineers, security auditors, and system maintainers.

## 2. System Architecture and Component Interaction

### 2.1 Monorepo Structure and Packaging
The codebase is structured as a Python monorepo containing two decoupled packages alongside shared documentation, deployment automation, and testing harnesses:

```text
VenueDesk-Agent/
├── venuedesk-backend/            # Flask Control Plane application package
│   ├── app/
│   │   ├── api/                  # REST and Web UI blueprints (agents, assets, devices, admin_infra)
│   │   ├── models/               # SQLAlchemy ORM models and enumerated types
│   │   ├── security/             # Ed25519 signatures, tokens, CSRF defense, and RBAC
│   │   ├── services/             # Domain logic (identity, enrollment, jobs, telemetry, audit)
│   │   └── templates/            # Bootstrap 5 server-rendered administrative templates
│   ├── tests/                    # Backend unit, integration, and UI test suites
│   └── Dockerfile                # Production container specification
├── venuedesk-agent/              # Cross-platform endpoint daemon package
│   ├── agent/
│   │   ├── collectors/           # Hardware evidence, system, network, and storage collectors
│   │   ├── communication/        # Signed HTTP client, backoff retry, and enrollment
│   │   ├── identity/             # KeyStore, fingerprint canonicalizer, and evidence model
│   │   ├── jobs/                 # Allowlisted remote job handlers, scheduler, and executor
│   │   └── storage/              # SQLite state database and priority outbox queue
│   ├── installers/               # Linux systemd units and Windows PowerShell installers
│   └── tests/                    # Agent unit and security verification tests
├── docs/                         # Technical, operations, and architectural documentation
├── tools/                        # Standalone fleet simulation tools (fake_endpoint.py)
└── tests/e2e/                    # Multi-stage end-to-end integration test suite
```

### 2.2 Component Interaction Overview

```
+---------------------------------------------------------------------------------+
|                               Physical Workstation                              |
|                                                                                 |
|  +--------------------+      +--------------------+      +-------------------+  |
|  | Hardware Collectors| ---> | Evidence Normalizer| ---> | Canonical Hasher  |  |
|  +--------------------+      +--------------------+      +-------------------+  |
|                                                                    |            |
|  +--------------------+      +--------------------+                v            |
|  | Priority Outbox    | <--- |   Agent Daemon     | <--- [ Local FileKeyStore ] |
|  | (SQLite buffer)    |      | (Heartbeat / Jobs) |       (Ed25519 PrivKey)     |
|  +--------------------+      +--------------------+                             |
+----------------------------------------|----------------------------------------+
                                         | HTTPS (Ed25519 Request Signing)
                                         v
+---------------------------------------------------------------------------------+
|                             Control Plane Backend                               |
|                                                                                 |
|  +--------------------+      +--------------------+      +-------------------+  |
|  | Signature / Nonce  | ---> | Identity Decision  | ---> | State & Telemetry |  |
|  | Auth Filter        |      | Engine             |      | Persistence       |  |
|  +--------------------+      +--------------------+      +-------------------+  |
|            |                                                       |            |
|            v                                                       v            |
|  +--------------------+                                  +-------------------+  |
|  | Bootstrap 5 UI /   |                                  | PostgreSQL /      |  |
|  | RBAC / CSRF Guard  |                                  | SQLite Database   |  |
|  +--------------------+                                  +-------------------+  |
+---------------------------------------------------------------------------------+
```

## 3. Cryptographic Protocols and Security Invariants

### 3.1 Asymmetric Request Authentication (Agent to Server)
Every authenticated request from an enrolled agent to the control plane is digitally signed using an Ed25519 private key generated locally on the endpoint.
The agent transmits the following cryptographic headers on each request:

- `X-Device-ID`: The assigned physical device identifier (format `VD-DEVICE-XXXXXXXX`).
- `X-Timestamp`: The current UTC unix timestamp in seconds (integer string).
- `X-Nonce`: A single-use 32-character hexadecimal UUID4 string.
- `X-Key-Version`: The integer credential version matching the device record (defaults to `1`).
- `X-Signature`: Base64-encoded raw Ed25519 signature computed over the canonical string.

#### Canonical String Representation
The canonical payload string is constructed by concatenating request components with newline characters (`\n`) without trailing whitespace:

```text
{HTTP_METHOD_UPPER}\n{PATH_WITH_QUERY}\n{X-Timestamp}\n{X-Nonce}\n{sha256_hex(raw_body_bytes)}
```

#### Server-Side Verification Pipeline
The backend decorator [`@require_device_auth`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/venuedesk-backend/app/security/signatures.py) evaluates requests through a strict security pipeline:
1. **Device Status Validation:** Confirms the device exists in the database and is in `ACTIVE`, `PENDING_VERIFICATION`, `OFFLINE`, or `PENDING_REVERIFICATION` state.
   If the device is `REVOKED`, `SUSPENDED`, or `RETIRED`, the request is immediately rejected with HTTP 403 `{"error": "device_blocked"}`.
2. **Credential Version Match:** Asserts that `X-Key-Version` matches `device.credential_version`.
   Mismatches return HTTP 401 `{"error": "key_version_mismatch"}`.
3. **Clock-Skew Validation:** Enforces `abs(current_utc_time - request_timestamp) <= CLOCK_SKEW_SECONDS` (default 120 seconds).
   Skewed requests return HTTP 401 `{"error": "clock_skew"}`.
4. **Nonce Replay Prevention:** Checks whether `X-Nonce` has been recorded for the specified device within the replay window.
   Replayed nonces return HTTP 401 `{"error": "nonce_replayed"}`.
   Valid nonces are stored in [`request_nonces`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/venuedesk-backend/app/models/nonce.py) with an expiration time equal to `timestamp + (2 * CLOCK_SKEW_SECONDS)`.
5. **Signature Cryptographic Verification:** Computes the SHA-256 hash of the raw HTTP request body, constructs the canonical string, and verifies the Ed25519 signature against the stored public key.
   Invalid signatures return HTTP 401 `{"error": "invalid_signature"}`.

### 3.2 Proof of Possession Enrollment Handshake
During initial enrollment, the agent must prove ownership of the private key corresponding to its submitted public key without transmitting the private key:

```text
proof_payload = f"enroll\n{sha256(raw_pairing_token)}\n{timestamp}\n{nonce}".encode("utf-8")
proof_signature = base64_encode( Ed25519_sign(proof_payload) )
```

The control plane verifies this signature against the supplied public key before evaluating or consuming the pairing token.

### 3.3 KeyStore Architecture
The agent abstracts private key operations behind the [`KeyStore`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/venuedesk-agent/agent/identity/keys.py) interface:
- **`FileKeyStore` (Default):** Persists raw Ed25519 private keys to the local filesystem.
  - On Linux: Creates the key file with POSIX `0600` permissions (read/write by owner only).
  - On Windows: Uses DPAPI or configures restrictive NTFS Access Control Lists permitting only `SYSTEM` and `BUILTIN\Administrators`.
- **`TpmKeyStore` (Hardware Stub):** An interface stub configured for future hardware-backed TPM 2.0 key derivation that safely raises `NotImplementedError` if invoked without TPM support.

### 3.4 Secret and Token Redaction Filter
The logging subsystem [`agent/logging_setup.py`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/venuedesk-agent/agent/logging_setup.py) implements regex-based redaction filters.
All log output streams pass through filters that scrub pairing tokens (`PAIR-[A-Za-z0-9_-]+`), bearer tokens, passwords, and private key representations, replacing them with `[REDACTED]`.

## 4. Hardware Identity and Evidence Canon

### 4.1 Cross-Platform Evidence Collection
Hardware identity collectors degrade gracefully, catching platform exceptions and returning `None` instead of failing:

| Evidence Component | Linux Source | Windows Source | Fallback Behavior |
|---|---|---|---|
| Machine UUID | `/sys/class/dmi/id/product_uuid` or `/etc/machine-id` | `Get-CimInstance Win32_ComputerSystemProduct.UUID` | `None` |
| Motherboard Serial | `/sys/class/dmi/id/board_serial` | `Get-CimInstance Win32_BaseBoard.SerialNumber` | `None` |
| BIOS Serial | `/sys/class/dmi/id/bios_serial` | `Get-CimInstance Win32_BIOS.SerialNumber` | `None` |
| CPU Signature | `/proc/cpuinfo` model name and core count | `Get-CimInstance Win32_Processor.Name` | `None` |
| GPU Signature | `lspci` / `/sys/class/drm` / `nvidia-smi` | `Get-CimInstance Win32_VideoController.Name` | `None` |
| Storage Identities | `lsblk -J -o NAME,SERIAL,MODEL` | `Get-CimInstance Win32_DiskDrive.SerialNumber` | Empty list |
| Network MACs | `ip -j link` (physical adapters only) | `Get-CimInstance Win32_NetworkAdapterConfiguration` | Empty list |

### 4.2 Canonicalization Specification (`FINGERPRINT_VERSION = 1`)
Raw hardware strings undergo deterministic canonicalization before hashing:
1. **String Normalization:** Strings are trimmed, converted to lowercase, and internal whitespace is collapsed.
   Placeholder strings (such as `""`, `"none"`, `"to be filled by o.e.m."`, `"default string"`, `"0"`, `"unknown"`, and all-zero/all-F UUIDs) are normalized to `null`.
2. **List Sorting and Filtering:** Lists of GPUs, storage drives, and network interfaces are normalized, filtered to remove virtual adapters (such as `docker*`, `veth*`, `vmnet*`, `vbox*`, `lo`, `tun*`, `tap*`, `wg*`, `br-*`), sorted lexicographically, and deduplicated.
3. **Excluded Volatile Attributes:** IP addresses, DHCP hostnames, current CPU load, memory utilization, disk free space, uptime, running processes, logged-in users, and temperatures are strictly excluded from identity evidence.
4. **Serialization and Hashing:** The normalized structure is serialized using `json.dumps(obj, sort_keys=True, separators=(",", ":"))` and hashed using SHA-256 to generate the fingerprint hex string.

### 4.3 Salted HMAC Anonymization
To prevent leaking raw institutional hardware serial numbers across networks, individual hardware identifiers are hashed using HMAC-SHA256 with the deployment-wide secret salt (`DEPLOYMENT_SALT`):

```python
hashed_value = hmac.new(DEPLOYMENT_SALT, raw_value.lower().encode("utf-8"), hashlib.sha256).hexdigest()
```

The fingerprint is computed from canonical evidence locally on the endpoint; only HMAC hashes and the aggregate fingerprint are transmitted and stored in the database.

### 4.4 Hardware Anchor Classification
Evidence components are categorized into strong and supporting anchors:
- **Strong Anchors:** `machine_uuid_hash`, `motherboard_serial_hash`, `bios_serial_hash`, `tpm_identity`.
- **Supporting Anchors:** `cpu_signature`, `gpu_signature`, `disk_identity_hash`, `network_identity_hash`.

## 5. Identity Reconciliation and Decision Engine

### 5.1 Component Differential Analysis
When an authenticated device submits updated inventory or evidence, the server compares the observation against the last trusted snapshot:

| Observed Component Change | Emitted Event | Default Severity | Action Taken |
|---|---|---|---|
| IP Address or Hostname | `IP_CHANGED` / `HOSTNAME_CHANGED` | `LOW` | Update inventory snapshot; device remains `ACTIVE` |
| System RAM Capacity | `RAM_CHANGED` | `LOW` | Log event; update inventory |
| GPU Subsystem | `GPU_CHANGED` | `LOW` | Log event; update inventory |
| Operating System Family/Version | `OS_CHANGED` | `MEDIUM` | Upsert OS installation; log event |
| Storage Drive Set | `DISK_CHANGED` | `MEDIUM` | Log event; update inventory |
| Network Interface Set | `NIC_CHANGED` | `MEDIUM` | Log event; update inventory |
| Motherboard Serial | `MOTHERBOARD_CHANGED` | `HIGH` | Require administrative review |
| TPM Cryptographic Identity | `TPM_CHANGED` | `HIGH` | Require administrative review |
| Two or More Strong Anchors | `IDENTITY_CHANGE_DETECTED` | `HIGH` | Transition device to `PENDING_REVERIFICATION` |

### 5.2 Deterministic Decision State Machine
The server decision engine [`determine_device_identity(observation)`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/venuedesk-backend/app/services/identity_service.py) determines device state using deterministic logic:

```python
def determine_device_identity(obs: DeviceObservation) -> IdentityDecision:
    # 1. Cryptographic continuity
    if obs.valid_signature_for_active_device:
        return IdentityDecision.SAME_DEVICE

    # 2. Candidate discovery by matching hardware anchors
    candidates = find_candidates_by_evidence(obs)
    if not candidates:
        return IdentityDecision.UNKNOWN_DEVICE

    # 3. Disambiguation
    if len(candidates) > 1:
        return IdentityDecision.AMBIGUOUS

    # 4. Anchor strength verification
    matching_strong = count_matching_strong_anchors(candidates[0], obs)
    if matching_strong >= 2:
        return IdentityDecision.PENDING_REVERIFICATION

    return IdentityDecision.MANUAL_VERIFICATION
```

### 5.3 Advisory Similarity Scoring
The candidate similarity score uses configurable weights across hardware components:
- `machine_uuid`: 40%
- `motherboard_serial`: 25%
- `bios_serial`: 15%
- `cpu_signature`: 10%
- `disk_identity`: 5%
- `network_identity`: 5%

Missing components are excluded and the remaining weights are re-normalized to 100%.
**Security Invariant:** The similarity score is strictly advisory and used solely to rank candidates for human review.
No code path may create an asset link based on similarity score alone.

## 6. Database Schema and Model Specifications

The database schema is implemented with SQLAlchemy ORM and managed via Flask-Migrate (Alembic).

### 6.1 `assets` Table
Represents institutional inventory items.

| Column | Type | Constraints / Indexes | Description |
|---|---|---|---|
| `id` | BigInteger | PK, Autoincrement | Internal synthetic database identifier |
| `asset_id` | String(64) | Unique, Indexed | Institutional asset code (e.g., `VD-ASSET-000421`) |
| `asset_tag` | String(128) | Unique, Nullable | Human-readable physical barcode label |
| `asset_type` | Enum(AssetType) | Not Null | `DESKTOP`, `LAPTOP`, `SERVER`, `OTHER` |
| `department_id` | String(64) | Nullable, Indexed | Owning department code |
| `building_id` | String(64) | Nullable | Campus building identifier |
| `room_id` | String(64) | Nullable, Indexed | Campus room identifier |
| `location_label` | String(255) | Nullable | Human-friendly location text |
| `position_label` | String(64) | Nullable | Desk or bench coordinate (e.g., `Desk 07`) |
| `lifecycle_status` | Enum(AssetLifecycleStatus) | Not Null, Default `DRAFT` | `DRAFT`, `PENDING_AGENT`, `PENDING_VERIFICATION`, `VERIFIED`, `IN_SERVICE`, `MAINTENANCE`, `REASSIGNED`, `RETIRED`, `DISPOSED` |
| `verification_status` | Enum(AssetVerificationStatus) | Not Null, Default `UNVERIFIED` | `UNVERIFIED`, `VERIFIED`, `REVERIFICATION_REQUIRED` |
| `created_at` | DateTime(UTC) | Not Null | Record creation timestamp |
| `updated_at` | DateTime(UTC) | Not Null | Record modification timestamp |

### 6.2 `physical_devices` Table
Represents physical workstation hardware.

| Column | Type | Constraints / Indexes | Description |
|---|---|---|---|
| `id` | BigInteger | PK, Autoincrement | Internal synthetic database identifier |
| `device_id` | String(64) | Unique, Indexed | Device identifier (e.g., `VD-DEVICE-A8123F00`) |
| `device_public_key` | Text | Not Null | Base64-encoded Ed25519 raw public key |
| `credential_version` | Integer | Not Null, Default 1 | Monotonically incrementing key version |
| `status` | Enum(DeviceStatus) | Not Null, Default `ENROLLING` | `ENROLLING`, `ACTIVE`, `OFFLINE`, `PENDING_REVERIFICATION`, `SUSPENDED`, `REVOKED`, `RETIRED`, `UNCLAIMED` |
| `endpoint_type` | Enum(EndpointType) | Not Null, Default `PHYSICAL` | `PHYSICAL`, `VIRTUAL` |
| `first_seen` | DateTime(UTC) | Not Null | Timestamp of first successful enrollment |
| `last_seen` | DateTime(UTC) | Not Null, Indexed | Timestamp of most recent valid heartbeat |
| `created_at` | DateTime(UTC) | Not Null | Record creation timestamp |
| `updated_at` | DateTime(UTC) | Not Null | Record modification timestamp |

### 6.3 `asset_device_links` Table
Tracks relationships between assets and devices.

| Column | Type | Constraints / Indexes | Description |
|---|---|---|---|
| `id` | BigInteger | PK, Autoincrement | Internal synthetic database identifier |
| `asset_id` | BigInteger | FK(`assets.id`), Indexed | Referenced asset record |
| `device_id` | BigInteger | FK(`physical_devices.id`), Indexed | Referenced physical device record |
| `relationship_status` | Enum(RelationshipStatus) | Not Null, Default `ACTIVE` | `ACTIVE`, `CLOSED` |
| `linked_at` | DateTime(UTC) | Not Null | Timestamp when relationship was activated |
| `unlinked_at` | DateTime(UTC) | Nullable | Timestamp when relationship was closed |
| `linked_by` | String(128) | Not Null | User ID or `"system"` |
| `reason` | String(255) | Nullable | Reason for closure (e.g., `MOTHERBOARD_REPLACED`) |

**Constraint:** At most one `ACTIVE` link per asset and at most one `ACTIVE` link per device.

### 6.4 `device_identity_evidence` Table
Append-only hardware evidence snapshots.

| Column | Type | Constraints / Indexes | Description |
|---|---|---|---|
| `id` | BigInteger | PK, Autoincrement | Internal synthetic database identifier |
| `device_id` | BigInteger | FK(`physical_devices.id`), Indexed | Referenced physical device record |
| `machine_uuid_hash` | String(64) | Nullable, Indexed | Salted HMAC of machine UUID |
| `bios_serial_hash` | String(64) | Nullable, Indexed | Salted HMAC of BIOS serial |
| `motherboard_serial_hash`| String(64) | Nullable, Indexed | Salted HMAC of motherboard serial |
| `cpu_signature` | String(255) | Nullable | Normalized CPU model and core count |
| `gpu_signature` | Text | Nullable | Normalized GPU descriptor |
| `disk_identity_hash` | String(64) | Nullable | Salted HMAC of primary disk serial |
| `network_identity_hash` | String(64) | Nullable | Salted HMAC of physical MAC addresses |
| `tpm_identity` | String(64) | Nullable | Salted HMAC of TPM endorsement credential |
| `fingerprint` | String(64) | Not Null, Indexed | Canonical SHA-256 fingerprint hash |
| `fingerprint_version` | Integer | Not Null, Default 1 | Fingerprint algorithm version |
| `captured_at` | DateTime(UTC) | Not Null | Timestamp when evidence was captured |
| `trusted` | Boolean | Not Null, Default False | True when verified by admin or audit sign-off |

### 6.5 `os_installations` Table
Tracks operating system environments.

| Column | Type | Constraints / Indexes | Description |
|---|---|---|---|
| `id` | BigInteger | PK, Autoincrement | Internal synthetic database identifier |
| `device_id` | BigInteger | FK(`physical_devices.id`), Indexed | Referenced physical device record |
| `os_family` | Enum(OsFamily) | Not Null | `WINDOWS`, `LINUX`, `OTHER` |
| `os_name` | String(128) | Not Null | OS distribution or edition name |
| `os_version` | String(128) | Not Null | OS release or kernel version |
| `architecture` | String(64) | Not Null | CPU architecture (e.g., `x86_64`) |
| `os_machine_id_hash` | String(64) | Not Null | SHA-256 of `/etc/machine-id` or Windows MachineGuid |
| `agent_instance_id` | String(64) | Not Null, Indexed | UUID4 identifying local agent runtime |
| `first_seen` | DateTime(UTC) | Not Null | First discovery timestamp |
| `last_seen` | DateTime(UTC) | Not Null | Most recent check-in timestamp |
| `status` | Enum(OsInstallationStatus) | Not Null, Default `ACTIVE` | `ACTIVE`, `HISTORICAL` |

### 6.6 Additional System Tables
- **`enrollment_tokens`**: Stores SHA-256 token hashes, asset FK, expiration timestamps, and consumption state (`ACTIVE`, `USED`, `EXPIRED`, `REVOKED`).
- **`telemetry`**: Time-series store tracking CPU, RAM, disk, network RX/TX, uptime, load averages, and GPU utilization indexed by `(device_id, timestamp)`.
- **`device_events`**: Chronological event timeline recording identity changes, heartbeat misses, hardware modifications, and security alerts.
- **`device_jobs`**: Allowlisted job queue tracking dispatch state, parameters, expiration, and JSON execution results.
- **`audit_logs`**: Append-only administrative compliance log recording actor identity, action type, entity references, and old/new state diffs.
- **`request_nonces`**: Nonce tracking table with composite uniqueness on `(device_id, nonce)` and indexed expiration for automated purging.
- **`device_inventory`**: Single-row-per-device snapshot storing latest observed hostnames, IP addresses, MAC lists, storage lists, and agent versions.

## 7. API Specifications and Contracts

### 7.1 Agent Endpoints (`/api/v1/agents/*`)

#### `POST /api/v1/agents/enroll` (Unauthenticated except for token)
- **Purpose:** Onboard a new endpoint or register an unclaimed device.
- **Payload:** Raw pairing token, public key, proof of possession signature, hardware evidence, initial inventory, OS details, and agent instance ID.
- **Response (200 OK):**
  ```json
  {
    "device_id": "VD-DEVICE-A8123F00",
    "asset_id": "VD-ASSET-000421",
    "status": "PENDING_VERIFICATION",
    "credential": {
      "type": "public_key_registered",
      "credential_version": 1
    },
    "config": {
      "heartbeat_seconds": 60,
      "telemetry_seconds": 60,
      "inventory_seconds": 21600,
      "jobs_poll_seconds": 60
    }
  }
  ```

#### `POST /api/v1/agents/heartbeat` (Signed)
- **Purpose:** Transmit periodic liveness signal and check for pending remote jobs.
- **Headers:** `X-Device-ID`, `X-Timestamp`, `X-Nonce`, `X-Key-Version`, `X-Signature`.
- **Payload:** `{"agent_instance_id": "<uuid>"}`.
- **Response (200 OK):** `{"status": "ok", "pending_jobs": false}`.
- **Conflict (403 Forbidden):** Returns `{"error": "device_suspended"}` if duplicate instance detected.

#### `POST /api/v1/agents/telemetry` (Signed)
- **Purpose:** Ingest buffered time-series metrics samples.
- **Payload:** `{"samples": [ { "timestamp": 1760000000, "cpu_percent": 15.2, ... } ]}` (capped at 500 samples per request).
- **Response (200 OK):** `{"status": "ok", "ingested": 10}`.

#### `POST /api/v1/agents/inventory` (Signed)
- **Purpose:** Transmit periodic full system hardware and software inventory.
- **Payload:** Detailed hardware lists, network interfaces, storage drives, and evidence payload.
- **Response (200 OK):** `{"status": "ok", "reconciliation": {"changes_detected": false}}`.

#### `POST /api/v1/agents/recover` (Signed with new key)
- **Purpose:** Request identity re-association after an OS reinstall.
- **Payload:** New public key, proof of possession, hardware evidence, and agent instance ID.
- **Response (202 Accepted):** `{"status": "pending_approval", "candidate_device_id": "VD-DEVICE-A8123F00"}`.

#### `POST /api/v1/agents/jobs/poll` and `POST /api/v1/agents/jobs/{id}/result` (Signed)
- **Purpose:** Fetch dispatched allowlisted jobs and report execution status and output payloads.

### 7.2 Administrative REST API (`/api/v1/admin/*`)
Requires user authentication and role validation (`infra_admin` or `infra_viewer`):
- `POST /api/v1/admin/assets/{id}/token`: Generates a single-use pairing token for the specified asset.
- `POST /api/v1/admin/devices/{id}/pair`: Manually pairs an unclaimed device to an asset.
- `POST /api/v1/admin/devices/{id}/verify`: Submits physical verification data and promotes asset to `IN_SERVICE`.
- `POST /api/v1/admin/devices/{id}/approve-recovery`: Approves a pending OS reinstall recovery request.
- `POST /api/v1/admin/devices/{id}/replace-motherboard`: Closes active link and generates a new token for the asset.
- `POST /api/v1/admin/devices/{id}/jobs`: Dispatches an allowlisted job to an active device.
- `POST /api/v1/admin/devices/{id}/revoke`: Revokes device credentials and severs active asset links.

## 8. Remote Jobs Subsystem and Execution Sandboxing

### 8.1 Job Lifecycle States
Jobs progress through explicit lifecycle states:
`PENDING` -> `DISPATCHED` -> `RUNNING` -> `SUCCEEDED` / `FAILED` / `EXPIRED` / `CANCELLED`.

### 8.2 Allowlisted Handlers
The agent executes remote jobs strictly through pre-compiled Python handlers:

1. **`REFRESH_INVENTORY`:** Triggers immediate execution of local inventory collectors and submits the result to `/inventory`.
2. **`COLLECT_DIAGNOSTICS`:** Runs diagnostic network and system probes restricted to targets in `diagnostic_allowlist` (defaults to `127.0.0.1`, `localhost`).
3. **`COLLECT_LOGS`:** Retrieves the trailing lines of local agent logs capped at 1 MB, applying automated secret and token redaction.
4. **`RESTART_APPROVED_SERVICE`:** Restarts a local system service using `systemctl` or Windows Service Manager.
   The service name must exist in the agent local configuration `approved_services` array; unapproved services are rejected.
5. **`REFRESH_CONFIGURATION`:** Re-reads `config.toml` and updates local polling intervals.
6. **`RUN_NETWORK_DIAGNOSTIC`:** Executes ping or traceroute probes with strict IP/hostname allowlisting and port range constraints.

### 8.3 Zero `shell=True` Security Policy
Under no circumstances may the agent invoke shell interpreters (`shell=True`, `/bin/sh`, `cmd.exe`, or `powershell.exe -Command`).
All sub-process executions pass arguments as explicit lists directly to the target executable.
An automated test continuously scans the agent source tree with regular expressions to ensure `shell=True` is never introduced.

## 9. Local Agent Storage and Outbox Architecture

### 9.1 Local SQLite Schema (`agent_state.db`)
The agent maintains local operational state in SQLite:
- `identity`: Stores `device_id`, `agent_instance_id`, `credential_version`, and enrollment timestamps.
- `outbox`: Persistent message queue storing unsent telemetry, inventory updates, and job execution results.

### 9.2 Priority Levels and Queue Shedding
When the endpoint is disconnected, outbound messages are buffered in the outbox with explicit priorities:
- **Priority 0 (Critical):** Enrollment handshakes, identity drift events, and recovery responses.
  **Policy:** Priority-0 messages are never shed.
- **Priority 1 (Standard):** Full hardware inventory updates and job execution results.
- **Priority 2 (Telemetry):** High-frequency metrics samples.

If the outbox exceeds `outbox_max_items` (default 10,000) or items exceed `outbox_ttl_hours` (default 24 hours), the oldest Priority-2 telemetry samples are dropped first to preserve system stability and storage headroom.

## 10. Packaging, Deployment, and Installation Specifications

### 10.1 Linux Endpoint Packaging (systemd)
- **Unit Configuration:** Installed to `/etc/systemd/system/venuedesk-agent.service`.
- **Security Sandboxing Directives:**
  ```ini
  User=venuedesk
  Group=venuedesk
  ProtectSystem=strict
  ProtectHome=true
  NoNewPrivileges=true
  PrivateTmp=true
  ProtectKernelTunables=true
  ProtectControlGroups=true
  ReadWritePaths=/var/lib/venuedesk /var/log/venuedesk
  ```
- **Pre-Start Hardware Helper:** `/usr/local/libexec/venuedesk/venuedesk-evidence-helper` executes as `root` via `ExecStartPre` to refresh privileged DMI serial numbers into `/var/lib/venuedesk/cache/evidence_cache.json` before dropping privileges to the `venuedesk` user.

### 10.2 Windows Endpoint Packaging
- **Installer Script:** [`installers/windows/install.ps1`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/installers/windows/install.ps1) targets `C:\ProgramData\VenueDesk`.
- **NTFS Access Permissions:** Removes inheritance and restricts file access to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
- **Service Integration:** Uses [`service_wrapper.py`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/installers/windows/service_wrapper.py) running under Windows Service Control Manager.

### 10.3 Production Docker Compose Setup
- **PostgreSQL 16 Container:** Configured with persistent volumes and healthchecks.
- **Control Plane Container:** Runs Gunicorn WSGI server on port 5001 with production environment flags, secret keys, and database connection strings.

## 11. Verification Architecture and Testing Strategy

### 11.1 Automated Test Organization
The monorepo enforces high test coverage across three distinct testing tiers:

1. **Unit Testing:** Colocated tests verifying collectors, cryptographic signing, canonical string construction, token hashing, and CSRF token verification.
2. **Integration Testing:** In-process Flask testing evaluating database transactions, RBAC decorators, signature verification filters, and remote job polling.
3. **End-to-End Multi-Stage Lifecycle Suite:** Located in [`tests/e2e/test_full_lifecycle.py`](file:///C:/Users/amand/OneDrive/Documents/CBMS/VenueDesk-Agent/tests/e2e/test_full_lifecycle.py), driving an in-process server through all 11 lifecycle stages with real cryptographic signatures and database state.

### 11.2 Automated Quality Gates
Every build and commit must pass automated verification checks:
- `pytest -q`: 133 tests green.
- `ruff check .`: 0 lint and formatting errors.
- Identity service test coverage: >= 90%.
- Shell injection gate: 0 instances of `shell=True` across the agent codebase.
