# VenueDesk Agent — End-to-End Implementation Instructions

> **Audience:** an autonomous AI coding agent (Antigravity / CLI agent). Follow this file top to bottom.
> **Goal:** build the complete VenueDesk Agent system (endpoint agent + Flask control-plane additions + admin UI + tests + packaging) with minimal human interaction.
> **Source design:** `VenueDesk-Agent-Identity-and-Asset-Mapping-Technical-Specification.md` (v1.0). If this file and the spec ever conflict on *identity semantics*, the spec wins. If they conflict on *implementation details*, this file wins.

---

## 0. Operating Rules for the Agent (read first)

1. **Do not ask the user questions.** When something is ambiguous, pick the option marked "Default" in this file, implement it, and append a line to `docs/DECISIONS.md` (`date | decision | reason`).
2. **Work phase by phase** (Section 6). Do not start a phase until the previous phase's *Exit Criteria* pass. Run the tests after every phase. Commit after every phase with message `phase-N: <title>`.
3. **Never skip tests.** Every module gets unit tests. Every phase ends with `pytest -q` green.
4. **Inspect before building.** The existing VenueDesk Flask app may already exist in the workspace (look for a Flask app with Users/Bookings/Venues/Grievances/Assets). If found: integrate as a Blueprint and reuse its `db`, auth, and RBAC. If not found: create the standalone backend in `venuedesk-backend/` exactly as in Section 3 and make it runnable on its own. Record which path you took in `DECISIONS.md`.
5. **Security invariants (never violate):**
   - Never use IP, hostname, MAC, OS machine-id, CPU/GPU model, hardware fingerprint, or a confidence score as the Asset ID or as sole authority for Asset assignment.
   - Pairing tokens are single-use, short-lived, asset-scoped, stored **hashed**, never logged in plaintext, never used as a permanent credential.
   - Private keys never leave the endpoint and never go in a DB, a golden image, a QR code, or logs.
   - Remote jobs are **allowlisted**; no arbitrary shell execution anywhere.
   - The agent never overwrites institutional metadata (asset tag, department, room, etc.).
6. **Everything configurable lives in config** (env vars / `config.toml`), with sane defaults. No magic numbers in code.
7. **Cross-platform:** Agent must run on Linux (systemd) and Windows (service). All collectors must degrade gracefully (return `None`, never crash) when a value is unavailable or permission is missing.
8. **Deliverables are only "done"** when Section 10 (Definition of Done) is fully satisfied.

---

## 1. Technology Decisions (Defaults — do not revisit)

| Concern | Choice |
|---|---|
| Language (agent + backend) | Python 3.11+ |
| Backend | Flask 3, Flask-SQLAlchemy, Flask-Migrate (Alembic), marshmallow (validation) |
| DB | SQLite for dev/tests, PostgreSQL for prod (via `DATABASE_URL`) |
| Crypto | `cryptography` library — **Ed25519** device keys, SHA-256, HMAC-SHA256 |
| Agent HTTP | `httpx` (sync) with retry/backoff implemented in `retry.py` |
| System info | `psutil` (telemetry), `platform`, OS-specific evidence collectors |
| Windows evidence | PowerShell `Get-CimInstance` via `subprocess` (no WMI Python dependency) |
| Linux evidence | `/sys/class/dmi/id/*`, `/etc/machine-id`, `lsblk -J`, `ip -j link`, `lspci`/`/sys/class/drm` for GPU, `nvidia-smi` if present |
| Agent local store | SQLite (`agent_state.db`) — state + outbox |
| Private key storage | Interface `KeyStore` with implementations: `FileKeyStore` (default; `0600` perms on Linux, DPAPI-protected on Windows via `win32crypt` if available else ACL-restricted file), `TpmKeyStore` (stub that raises `NotSupported` unless implemented; selected only if config `key_store = "tpm"`). Document the limitation honestly. |
| Admin UI | Jinja2 templates + Bootstrap 5 (CDN) served by Flask, under `/admin/infrastructure/*` |
| Tests | `pytest`, `pytest-cov`, `responses`/Flask test client; agent↔backend integration tests run the Flask app in-process |
| Packaging | `pyproject.toml` (agent and backend separately), `docker-compose.yml` (backend + postgres) |
| Lint/format | `ruff` + `ruff format`; `mypy` (lenient) |
| CI | GitHub Actions workflow running lint + tests on Linux and Windows |

---

## 2. Repository Layout

Create a monorepo:

```text
venuedesk/
├── README.md
├── docs/
│   ├── DECISIONS.md
│   ├── ARCHITECTURE.md           # condensed from spec §3, §19, §72
│   ├── API.md                    # generated/maintained API contract
│   ├── RUNBOOK.md                # install, enroll, recover, rotate, revoke
│   └── THREAT_MODEL.md           # from spec §69
├── docker-compose.yml
├── .github/workflows/ci.yml
├── venuedesk-backend/            # Flask control plane (or integrate into existing app)
│   ├── pyproject.toml
│   ├── .env.example
│   ├── app/
│   │   ├── __init__.py           # create_app()
│   │   ├── config.py
│   │   ├── extensions.py
│   │   ├── models/{asset,device,enrollment,telemetry,audit,job,nonce}.py
│   │   ├── api/{agents,assets,devices,admin_infra}.py
│   │   ├── services/{enrollment_service,identity_service,device_service,verification_service,telemetry_service,job_service,audit_service}.py
│   │   ├── security/{signatures,tokens,replay,rbac}.py
│   │   ├── templates/infrastructure/*.html
│   │   └── cli.py                # flask commands: create-admin, seed-demo, purge-telemetry
│   ├── migrations/
│   └── tests/
├── venuedesk-agent/
│   ├── pyproject.toml
│   ├── config.example.toml
│   ├── agent/
│   │   ├── main.py  config.py  logging_setup.py
│   │   ├── identity/{device_id,keys,evidence,fingerprint,reconciliation}.py
│   │   ├── collectors/{system,hardware,storage,network,processes,services,gpu}.py
│   │   ├── communication/{client,enrollment,authentication,retry,heartbeat}.py
│   │   ├── storage/{database,outbox}.py
│   │   └── jobs/{scheduler,executor,handlers}.py
│   ├── installers/{linux/venuedesk-agent.service, linux/install.sh, windows/install.ps1, windows/service_wrapper.py}
│   ├── scripts/{simulate_fleet.py, dev_enroll.py}
│   └── tests/
└── tools/
    └── fake_endpoint.py          # simulates N endpoints (identical hardware) for end-to-end tests
```

---

## 3. Backend Data Model (implement exactly; add indexes noted)

All tables have `id` (PK, int/bigint autoincrement) plus the columns below. Use UTC timestamps (`DateTime(timezone=True)`), store as UTC. Enums are stored as strings with Python `enum.Enum` classes defined in `app/models/enums.py`.

### 3.1 `assets`
`asset_id` (str, unique, idx, format `VD-ASSET-{000421}` zero-padded 6 digits from a DB sequence/counter — **never** derived from hardware), `asset_tag` (str, unique, nullable), `asset_type` (DESKTOP/LAPTOP/SERVER/OTHER), `department_id`, `building_id`, `room_id`, `location_label`, `position_label`, `assigned_to`, `purchase_date`, `warranty_end`, `lifecycle_status`, `verification_status`, `notes`, `created_at`, `updated_at`.
- Lifecycle enum: `DRAFT, PENDING_AGENT, PENDING_VERIFICATION, VERIFIED, IN_SERVICE, MAINTENANCE, REASSIGNED, RETIRED, DISPOSED`.
- Reuse existing `departments/buildings/rooms` tables if the app has them; else keep these as nullable plain string/int columns.

### 3.2 `physical_devices`
`device_id` (str unique idx, `VD-DEVICE-{4 hex upper}` extended: use `VD-DEVICE-` + 8 uppercase hex from `secrets.token_hex(4)`; retry on collision), `device_public_key` (text, base64 raw Ed25519 public key), `device_certificate` (text, nullable — reserved), `credential_version` (int, default 1), `status` (ENROLLING/ACTIVE/OFFLINE/PENDING_REVERIFICATION/SUSPENDED/REVOKED/RETIRED/UNCLAIMED), `endpoint_type` (PHYSICAL/VIRTUAL), `first_seen`, `last_seen`, `last_verified_at`, `created_at`, `updated_at`.

### 3.3 `asset_device_links`
`asset_id` (FK assets), `device_id` (FK physical_devices), `relationship_status` (ACTIVE/CLOSED), `linked_at`, `unlinked_at`, `linked_by` (user id or "system"), `reason`, `verification_id` (nullable FK). **Constraint:** at most one `ACTIVE` link per asset and per device (partial unique index on PostgreSQL; enforce in service layer for SQLite).

### 3.4 `device_identity_evidence` (append-only snapshots)
`device_id`, `machine_uuid_hash`, `bios_serial_hash`, `motherboard_serial_hash`, `cpu_signature`, `gpu_signature`, `disk_identity_hash`, `network_identity_hash`, `tpm_identity` (nullable, hashed), `fingerprint` (hex SHA-256), `fingerprint_version` (int), `captured_at`, `evidence_version` (int), `trusted` (bool — true once an admin/verification confirmed this snapshot).

### 3.5 `os_installations`
`device_id`, `os_family` (WINDOWS/LINUX/OTHER), `os_name`, `os_version`, `architecture`, `os_machine_id_hash`, `agent_instance_id` (uuid4 generated locally on first agent run), `first_seen`, `last_seen`, `status` (ACTIVE/HISTORICAL). Upsert key: `(device_id, os_family, os_machine_id_hash)`. OS count is **derived**, never stored.

### 3.6 `enrollment_tokens`
`asset_id`, `token_hash` (SHA-256 hex of the raw token; unique), `expires_at`, `used_at`, `used_by_device_id`, `created_by`, `revoked_at`, `status` (ACTIVE/USED/EXPIRED/REVOKED).

### 3.7 `telemetry`
`device_id` (idx), `timestamp` (idx; composite idx `(device_id, timestamp)`), `cpu_percent`, `memory_percent`, `disk_percent`, `network_rx`, `network_tx`, `uptime`, `load_average`, plus nullable `gpu_percent`, `gpu_mem_percent`, `temperature_c`.

### 3.8 `device_events`
`device_id`, `event_type` (see §3.12), `severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL), `payload` (JSON), `occurred_at`, `created_at`, `acknowledged_by`, `acknowledged_at`.

### 3.9 `device_jobs`
`device_id`, `job_type` (allowlist enum §4.7), `payload` (JSON), `status` (PENDING/DISPATCHED/RUNNING/SUCCEEDED/FAILED/EXPIRED/CANCELLED), `created_by`, `created_at`, `started_at`, `completed_at`, `result` (JSON), `expires_at`.

### 3.10 `audit_logs`
`actor_id`, `actor_type` (USER/DEVICE/SYSTEM), `action`, `entity_type`, `entity_id`, `old_value` (JSON), `new_value` (JSON), `timestamp`, `ip_address`, `metadata` (JSON). Append-only: no update/delete service methods exist. Actions: `ASSET_CREATED, ASSET_VERIFIED, DEVICE_ENROLLED, DEVICE_LINKED, DEVICE_UNLINKED, DEVICE_REVOKED, IDENTITY_OVERRIDE, HARDWARE_CHANGE_APPROVED, ASSET_REASSIGNED, ASSET_RETIRED, TOKEN_CREATED, TOKEN_REVOKED, CREDENTIAL_ROTATED`.

### 3.11 `request_nonces`
`device_id`, `nonce` (unique with device_id), `expires_at` (idx). Purged by a periodic cleanup (CLI command + opportunistic purge on write).

### 3.12 Event types
`DEVICE_ENROLLED, HEARTBEAT_MISSED, IP_CHANGED, HOSTNAME_CHANGED, OS_CHANGED, HARDWARE_CHANGED, GPU_CHANGED, DISK_CHANGED, RAM_CHANGED, NIC_CHANGED, TPM_CHANGED, MOTHERBOARD_CHANGED, IDENTITY_CHANGE_DETECTED, DUPLICATE_DEVICE_IDENTITY, UNAUTHORIZED_ENROLLMENT, DEVICE_REVOKED, DEVICE_MOVED, OS_REINSTALL_DETECTED, UNCLAIMED_DEVICE_DISCOVERED`.

Also add a `device_inventory` table (current-state snapshot, one row per device, upserted): `device_id (unique)`, `hostname`, `ip_addresses (JSON)`, `mac_addresses (JSON)`, `cpu_model`, `cpu_cores`, `ram_total_mb`, `gpus (JSON)`, `disks (JSON)`, `os_summary`, `bios_version`, `tpm_present`, `agent_version`, `updated_at`. This is **observed technical state** — Agent is source of truth (spec §41).

---

## 4. Core Logic Specifications

### 4.1 Request signing (agent → server) — `security/signatures.py` and `communication/authentication.py`

Headers on every authenticated request:
```
X-Device-ID:   VD-DEVICE-XXXXXXXX
X-Timestamp:   unix seconds (int, UTC)
X-Nonce:       uuid4 hex (32 chars)
X-Key-Version: credential_version (int)
X-Signature:   base64( Ed25519_sign( canonical_string ) )
```
Canonical string (exact, `\n`-joined, no trailing newline):
```
{HTTP_METHOD_UPPER}\n{PATH_WITH_QUERY}\n{X-Timestamp}\n{X-Nonce}\n{sha256_hex(body_bytes)}
```
Server verification (in a decorator `@require_device_auth`), reject with `401` and a generic body `{"error":"unauthorized"}` (log the specific reason server-side + audit/event where useful):
1. device exists AND `status in (ACTIVE, PENDING_VERIFICATION, OFFLINE, PENDING_REVERIFICATION)`; `REVOKED/SUSPENDED/RETIRED` → 403 `{"error":"device_blocked"}`.
2. `X-Key-Version == credential_version` (else 401 `key_version_mismatch`).
3. `abs(now - timestamp) <= CLOCK_SKEW_SECONDS` (default **120**).
4. nonce not seen for this device within window; insert nonce with `expires_at = now + 2*skew`.
5. signature valid against stored public key.
Compare with `hmac.compare_digest` where applicable. Body hash uses the **raw** request bytes.

### 4.2 Enrollment tokens — `security/tokens.py`
- Generate: `"PAIR-" + secrets.token_urlsafe(32)`. Store only `sha256(token)`. Show the raw token **once** to the admin (UI + API response) and never again.
- TTL default **24h** (`ENROLLMENT_TOKEN_TTL_HOURS`), one-time use, scoped to exactly one asset. Generating a new token for an asset **revokes** previous ACTIVE tokens for it.
- Validation is atomic: in one DB transaction, `SELECT … FOR UPDATE` (or equivalent) the token row, check status/expiry, mark `USED`. Two concurrent enrollments with the same token → exactly one succeeds.
- Rate-limit `/agents/enroll` per source IP (default 10/min) and log failures as `UNAUTHORIZED_ENROLLMENT` events (no device_id → store under audit_logs with actor_type SYSTEM).

### 4.3 Enrollment flow — `POST /api/v1/agents/enroll` (unauthenticated except for token)

Request:
```json
{
  "enrollment_token": "PAIR-...",
  "device_public_key": "<base64 raw ed25519 pubkey>",
  "proof_of_possession": "<base64 signature over 'enroll\\n{token_sha256}\\n{timestamp}\\n{nonce}'>",
  "timestamp": 1760000000, "nonce": "uuid-hex",
  "identity_evidence": { "machine_uuid":"...", "bios_serial":"...", "motherboard_serial":"...", "cpu":"...", "gpus":[], "disks":[], "nics":[], "tpm_identity":null, "fingerprint":"hex", "fingerprint_version":1 },
  "inventory": { "hostname":"...", "ip_addresses":[], "...": "..." },
  "os": { "family":"LINUX", "name":"Ubuntu", "version":"24.04", "architecture":"x86_64", "os_machine_id_hash":"..." },
  "agent_version":"0.1.0", "agent_instance_id":"uuid"
}
```
Server steps (single transaction): validate schema → verify proof-of-possession with the supplied public key → atomically consume token → create `PhysicalDevice` (status `PENDING_VERIFICATION`) → create `AssetDeviceLink` ACTIVE → insert evidence snapshot (`trusted=false`) → upsert OS installation + inventory → set asset `lifecycle_status=PENDING_VERIFICATION` → audit `DEVICE_ENROLLED` + `DEVICE_LINKED` → return:
```json
{ "device_id":"VD-DEVICE-A8123F00", "asset_id":"VD-ASSET-000421", "status":"PENDING_VERIFICATION",
  "credential": {"type":"public_key_registered","credential_version":1},
  "config": { "heartbeat_seconds":60, "telemetry_seconds":60, "inventory_seconds":21600, "jobs_poll_seconds":60 } }
```
(No server-issued secret is required: the registered public key *is* the credential. `device_certificate` is reserved for future mTLS.)

### 4.4 Unclaimed Device Mode (spec §26)
`POST /api/v1/agents/enroll` **without** a token, only when `ALLOW_UNCLAIMED_ENROLLMENT=true` (default **false**). Creates `PhysicalDevice` with `status=UNCLAIMED`, **no link**, emits `UNCLAIMED_DEVICE_DISCOVERED`. An admin later pairs it to an asset via `POST /api/v1/admin/devices/{device_id}/pair {asset_id}` which creates the link and moves the device to `PENDING_VERIFICATION`. Never auto-map by hostname/IP/CPU/GPU/MAC/score.

### 4.5 Fingerprint & evidence — `identity/evidence.py`, `identity/fingerprint.py`
Canonicalization (versioned, `FINGERPRINT_VERSION = 1`):
- Strings: trim, lowercase, collapse internal whitespace; treat `""`, `"none"`, `"to be filled by o.e.m."`, `"default string"`, `"0"`, `"unknown"`, all-zero/all-F UUIDs as **missing → `null`**.
- Lists (gpus, disks, nics): normalize each element, drop missing, **sort**, dedupe. Exclude virtual NICs (docker*, veth*, vmnet*, vbox*, lo, tun*, tap*, wg*, br-*, loopback) and USB tethering adapters.
- Excluded entirely: IP, hostname, utilization, free space, uptime, processes, current user, temperature.
- Serialize with `json.dumps(obj, sort_keys=True, separators=(",",":"))`, UTF-8, then `SHA-256` hex.
- **Hash individual sensitive identifiers** with `HMAC-SHA256(key=DEPLOYMENT_SALT, msg=value)` before sending (`machine_uuid_hash`, `bios_serial_hash`, `motherboard_serial_hash`, `disk_identity_hash`, `network_identity_hash`). `DEPLOYMENT_SALT` is a config value shared by agent and backend deployment (set in agent config; documented in RUNBOOK). The fingerprint is computed from the **canonical raw evidence** locally; only hashes + fingerprint are transmitted/stored.
- Evidence dataclass `IdentityEvidence` with `strong_anchors()` returning the set of present anchors among `{machine_uuid, motherboard_serial, bios_serial, tpm_identity}`.

### 4.6 Reconciliation & severity — `identity/reconciliation.py` (agent-side detection) + `services/identity_service.py` (server-side authority)
On each inventory/identity update from an **authenticated** device, the server compares the new snapshot to the last `trusted=true` snapshot (fallback: the latest snapshot):

| Field changed | Event | Severity |
|---|---|---|
| ip / hostname | IP_CHANGED / HOSTNAME_CHANGED | LOW |
| RAM total | RAM_CHANGED | LOW |
| GPU set | GPU_CHANGED | LOW |
| OS family/name/version | OS_CHANGED | MEDIUM |
| disk identity set | DISK_CHANGED | MEDIUM |
| NIC set | NIC_CHANGED | MEDIUM |
| motherboard serial | MOTHERBOARD_CHANGED | HIGH |
| TPM identity | TPM_CHANGED | HIGH |
| ≥2 strong anchors changed (machine_uuid, motherboard, bios, tpm) | IDENTITY_CHANGE_DETECTED | HIGH (+ device → `PENDING_REVERIFICATION`) |

Severity map is configurable (`IDENTITY_SEVERITY_POLICY` JSON in config). A change **never** creates a new Asset. Always store the new snapshot (history is retained, spec §60) with `trusted=false` until an admin approves via `POST /api/v1/admin/devices/{id}/approve-hardware-change`.

### 4.7 Identity decision engine — `identity_service.determine_device_identity(observation)`
Implement exactly (spec §37), returning an enum `IdentityDecision {SAME_DEVICE, UNKNOWN_DEVICE, PENDING_REVERIFICATION, AMBIGUOUS, MANUAL_VERIFICATION}`:
```python
def determine_device_identity(obs):
    if obs.valid_signature_for_active_device:        # cryptographic continuity
        return SAME_DEVICE
    candidates = find_candidates_by_evidence(obs)    # strong anchors first, then supporting
    if not candidates:
        return UNKNOWN_DEVICE
    if len(candidates) > 1:
        return AMBIGUOUS
    if evidence_is_strong(candidates[0], obs):       # ≥2 strong anchors match
        return PENDING_REVERIFICATION
    return MANUAL_VERIFICATION
```
`similarity_score(a, b)` uses configurable weights (default: machine_uuid 40, motherboard 25, bios 15, cpu 10, disk 5, nic 5; missing anchors are excluded and the remainder re-normalized). **The score is only used to rank candidates for recovery/review. No code path may link an Asset based on score alone.** Add a unit test that asserts this (a 99.9% match from an unenrolled device with no token yields `PENDING_REVERIFICATION`/`MANUAL_VERIFICATION`, never a link).

### 4.8 Recovery (OS reinstall, spec §22, §62)
A fresh agent (new key, no token) posts to `POST /api/v1/agents/recover` with evidence. Server runs the decision engine:
- Exactly one candidate with strong anchors → create a **recovery request** (device `PENDING_REVERIFICATION`, event `OS_REINSTALL_DETECTED`) and surface it in admin UI. Admin approves → server rotates the stored public key to the new agent key, `credential_version += 1`, closes old OS installation (`HISTORICAL`), creates new OS installation. Alternatively admin generates a fresh asset-scoped re-pairing token.
- Zero/ambiguous → remains UNCLAIMED / manual pairing.
Until approved, the recovering agent may only call `/recover` status polling and heartbeat-lite (`/api/v1/agents/recover/status`); all other endpoints return 403.

### 4.9 Duplicate device detection (spec §39)
In heartbeat handling: if the same `device_id` sends heartbeats whose `agent_instance_id` differs from the registered one **or** whose evidence fingerprint differs materially from last trusted snapshot **and** a heartbeat from the other instance arrived within `DUPLICATE_WINDOW_SECONDS` (default 120) → emit `DUPLICATE_DEVICE_IDENTITY` (CRITICAL), set device `SUSPENDED`, audit it. Never auto-merge.

### 4.10 Remote jobs (allowlist) — `jobs/handlers.py`
Allowed `job_type`s only: `REFRESH_INVENTORY, COLLECT_DIAGNOSTICS, COLLECT_LOGS, RESTART_APPROVED_SERVICE, REFRESH_CONFIGURATION, RUN_NETWORK_DIAGNOSTIC`.
- `RESTART_APPROVED_SERVICE` only for service names listed in the agent's local `approved_services` config (server cannot extend that list).
- `RUN_NETWORK_DIAGNOSTIC`: ping/DNS/TCP-connect to targets matching a configured allowlist of hosts/CIDRs; no arbitrary args reach a shell (use `subprocess.run([...], shell=False)` with validated args).
- `COLLECT_LOGS`: only the agent's own log files + (optionally) configured log paths; size cap 1 MB, redact tokens.
- Unknown job type → reject, report `FAILED` with `error="job_type_not_allowed"`.
Flow: admin creates job → agent `GET /jobs` (returns PENDING, marks DISPATCHED) → executes → `POST /jobs/{id}/result`. Jobs expire (`expires_at`, default 1h).

---

## 5. API Contract (implement all; document in `docs/API.md`)

### Agent API (device-authenticated per §4.1 unless noted)
| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/agents/enroll` | token or unclaimed mode (§4.3/4.4) — unauthenticated, rate-limited |
| POST | `/api/v1/agents/recover` | §4.8 — unauthenticated, rate-limited |
| GET | `/api/v1/agents/recover/status` | polling for recovering agent (signed by new key; limited) |
| POST | `/api/v1/agents/heartbeat` | lightweight: `{device_id,timestamp,agent_version,agent_instance_id,status}`; updates `last_seen`; device `OFFLINE→ACTIVE`; returns `{"server_time":..., "config_version":N, "pending_jobs":bool}` |
| POST | `/api/v1/agents/inventory` | full inventory + OS; triggers reconciliation |
| POST | `/api/v1/agents/identity` | identity evidence snapshot; triggers reconciliation |
| POST | `/api/v1/agents/telemetry` | batch: `{"samples":[{...},...]}` max 500 samples |
| GET | `/api/v1/agents/config` | returns intervals + `config_version` |
| GET | `/api/v1/agents/jobs` | pending jobs for this device |
| POST | `/api/v1/agents/jobs/<job_id>/result` | job result |
| POST | `/api/v1/agents/rotate-credential` | agent sends new public key signed by **old** key; server bumps `credential_version` |

### Admin API (session/RBAC; roles: `infra_admin`, `infra_viewer`; reuse existing roles if present)
`POST/GET/PATCH /api/v1/admin/assets`, `POST /api/v1/admin/assets/<asset_id>/pairing-token` (returns raw token once), `DELETE …/pairing-token` (revoke), `GET /api/v1/admin/devices`, `GET /api/v1/admin/devices/unclaimed`, `POST /…/devices/<id>/pair`, `POST …/verify`, `POST …/unlink`, `POST …/approve-hardware-change`, `POST …/approve-recovery`, `POST …/rotate-credential`, `POST …/revoke`, `GET …/devices/<id>/identity-history`, `GET …/devices/<id>/telemetry?from&to`, `GET …/devices/<id>/events`, `POST …/devices/<id>/jobs`, `GET /api/v1/admin/audit`, `GET /api/v1/admin/events`.
Every state-changing admin endpoint writes an `audit_logs` row (old/new values) and enforces RBAC. Pagination (`page`, `per_page` ≤ 100) on all list endpoints. Consistent error shape `{"error": "<code>", "message": "..."}`.

### Verification (spec §57)
`POST /…/devices/<id>/verify` body: `{verified_by(auto from session), verification_method: ADMIN_CONFIRMATION|QR_SCAN|SERIAL_CHECK|ENROLLMENT_TOKEN, observed_asset_tag, observed_serial, observed_location, notes}`. On success: store verification record, mark latest evidence snapshot `trusted=true`, device → `ACTIVE`, asset `verification_status=VERIFIED`, `lifecycle_status=IN_SERVICE` (if previously PENDING_*), set `last_verified_at`, audit `ASSET_VERIFIED`. Add a `verifications` table with those fields.

### Offline detection
A background job (APScheduler in-process for dev; Celery-ready service function `mark_offline_devices()`) marks devices `OFFLINE` when `now - last_seen > 3 * heartbeat_seconds` and emits `HEARTBEAT_MISSED`. Provide CLI `flask mark-offline` too.

---

## 6. Phased Build Plan

Each phase: implement → write tests → run `pytest -q` and `ruff check` → commit. **Exit Criteria** must all be true to proceed.

### Phase 0 — Scaffolding
1. Create the repo layout (Section 2), `pyproject.toml` for both packages, `.env.example`, `config.example.toml`, `docker-compose.yml` (backend + postgres), CI workflow, `docs/DECISIONS.md`.
2. Backend `create_app()` with config classes (Dev/Test/Prod), extensions, health route `GET /healthz`.
**Exit:** `pip install -e ./venuedesk-backend[dev] ./venuedesk-agent[dev]` works; `pytest` runs (even with trivial tests); `GET /healthz` returns 200.

### Phase 1 — Database
Implement all models in §3, enums, Alembic initial migration, asset ID generator (counter table or sequence; must be race-safe), `seed-demo` CLI (2 assets: AI-LAB-PC-07 and CSE-LAB-PC-12, plus an admin user if no auth exists). Enforce single-ACTIVE-link rule.
**Tests:** model constraints, asset ID uniqueness under concurrent creation, link uniqueness, nonce uniqueness.
**Exit:** `flask db upgrade` works on SQLite and PostgreSQL (docker-compose); tests green.

### Phase 2 — Security primitives
`security/tokens.py` (generate/hash/validate/atomic consume), `security/signatures.py` (canonical string, verify), `security/replay.py` (nonce store + purge), `security/rbac.py`, `@require_device_auth`.
**Tests:** token hashing never stores raw token; expiry; reuse rejection; concurrent consume (threads) → exactly one wins; signature valid/invalid/tampered body/tampered path; timestamp skew; nonce replay; revoked device blocked; key-version mismatch.
**Exit:** all above pass.

### Phase 3 — Agent identity core
Implement `KeyStore` (File + stub TPM), `keys.py` (Ed25519 gen/sign/load), `device_id.py` (local `agent_instance_id` + stored `device_id`), collectors (§4.5 sources) with graceful degradation, `evidence.py`, `fingerprint.py` (canonicalization + versioned hash + HMAC field hashes), local `storage/database.py`.
**Tests:** canonicalization (case/whitespace/order/placeholder values/virtual NIC exclusion), fingerprint stability across runs, fingerprint excludes volatile fields, collectors return `None` safely when commands are missing (mock subprocess), key file permissions, golden-image safety (state file absent → new key generated, never copied).
**Exit:** `python -m agent.main --print-identity` prints evidence JSON (hashes only, no private key) on the dev machine.

### Phase 4 — Enrollment
Backend `enrollment_service` + `/enroll` (token mode; unclaimed mode behind flag), admin pairing-token endpoints, agent `enrollment.py`, CLI `agent enroll --server URL --token PAIR-...`. Agent persists `device_id` + key and refuses to re-enroll if already enrolled unless `--force-reenroll` (which requires a new token).
**Tests (integration, in-process):** happy path creates Device + Link + evidence + OS + inventory + audit; second use of token fails; expired/revoked token fails; wrong asset scope impossible; proof-of-possession mismatch fails; **two near-identical fake endpoints with different tokens map to different assets/devices** (acceptance test 6); unclaimed mode off by default; rate limiting.
**Exit:** `tools/fake_endpoint.py --count 3` enrolls three endpoints against a local server successfully.

### Phase 5 — Authenticated communication
Agent `client.py` (signing every request via `authentication.py`), `retry.py` (exponential backoff with jitter, max attempts configurable, honors `Retry-After`), `heartbeat.py`; backend heartbeat/config endpoints; offline marking job; credential rotation endpoint + agent logic.
**Tests:** signed heartbeat accepted; unsigned rejected; replay rejected; clock-skew rejected; rotation (old key signs new key, old key then rejected); revoke → 403; offline marking.
**Exit:** fake endpoint runs heartbeat loop for 60 s against local server, `last_seen` updates, kill it → device `OFFLINE` after threshold (use shortened config in test).

### Phase 6 — Inventory, telemetry, offline outbox
Full collectors (system, hardware, storage, network, processes, services, gpu), inventory + telemetry endpoints, `telemetry_service` (batch insert, retention purge CLI `purge-telemetry --older-than-days 30`), agent `outbox.py` (SQLite queue with priority, max size, TTL, drop-lowest-priority-telemetry-first under pressure, ordered flush after reconnect).
**Priorities:** identity/event = 0 (never dropped unless TTL expired), inventory = 1, telemetry = 2.
**Tests:** outbox persists across restart; flush ordering; pressure dropping; backoff; large batch limits (>500 samples → 413); telemetry query API.
**Exit:** simulate server down 2 minutes → agent queues → server up → queue drains, no loss of priority-0 items.

### Phase 7 — Identity reconciliation & events
Implement §4.6 diffing, severity policy, snapshot history, `approve-hardware-change`, duplicate-device detection (§4.9), decision engine (§4.7) with similarity scoring, UNCLAIMED handling.
**Tests (all spec acceptance tests, §66, as named test functions):** `test_ip_change`, `test_hostname_change`, `test_gpu_upgrade`, `test_ssd_replacement`, `test_os_reinstall`, `test_identical_machine`, `test_duplicate_credential`, `test_motherboard_replacement`; plus `test_dual_boot_two_os_one_device`, `test_ram_upgrade`, `test_score_never_links_asset`, `test_golden_image_clones_are_distinct`.
**Exit:** all of the above pass; coverage for `identity_service` ≥ 90%.

### Phase 8 — Recovery & verification workflows
`/recover`, recovery status, `approve-recovery`, `verify` flow with `verifications` table, motherboard-replacement workflow (admin "replace endpoint": closes old link, creates re-pairing token for same asset; new PhysicalDevice created on enrollment; history retained — spec §25/§63).
**Tests:** OS reinstall end-to-end (new key → candidate found → pending → approve → old OS HISTORICAL, new OS ACTIVE, `credential_version` bumped, same asset/device); ambiguous candidates → manual; endpoint replacement keeps Asset ID, two links in history (one CLOSED).
**Exit:** pass.

### Phase 9 — Remote jobs
Job model/service, admin create-job, agent poll/execute/report, handlers (§4.10) with strict validation, expiry.
**Tests:** every allowlisted job; unknown job rejected; service restart rejected if not in local approved list; network diagnostic rejects non-allowlisted target; no `shell=True` anywhere (add a test that greps the agent source tree for `shell=True` and fails if found).
**Exit:** pass.

### Phase 10 — Admin UI
Pages under `/admin/infrastructure/` (Bootstrap 5, server-rendered, minimal JS; reuse existing layout/base template if the app has one):
1. **Devices list** (filter by status/department/online; shows asset tag, device id, status badge, last seen, OS list, IP).
2. **Device detail** exactly like spec §42: Asset block, Physical Device block, Hardware block, Current State block (latest telemetry + small sparkline using Chart.js CDN), OS installations list (§43), events, identity history timeline, asset history timeline (§44).
3. **Unclaimed devices** with "Pair to asset" dropdown.
4. **Asset page** with "Generate pairing token" (modal shows raw token **once** + copy button + enrollment command snippet `venuedesk-agent enroll --server … --token …` + optional QR image via `qrcode` lib containing only the short-lived token/pairing reference).
5. **Identity changes** queue with the §42 "IDENTITY CHANGE DETECTED" panel and `[Approve Hardware Change] [Investigate]` buttons; recovery requests queue.
6. **Verify device** form (§57 fields).
7. **Jobs** tab on device detail (create from allowlist dropdown, see results).
8. **Audit log** viewer with filters.
All mutating forms use CSRF protection and RBAC checks.
**Tests:** route smoke tests (200/403), a token-display-once test, CSRF presence.
**Exit:** `flask run` + `python tools/fake_endpoint.py --count 5 --telemetry` shows five live devices in the UI.

### Phase 11 — Packaging, deployment, hardening
1. `installers/linux/venuedesk-agent.service` (systemd; dedicated `venuedesk` user; `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/venuedesk-agent /var/log/venuedesk-agent`, `Restart=always`); `install.sh` creates user, dirs (`0700`), installs venv, writes config, enrolls with provided token, enables service. Note: reading `/sys/class/dmi/id/product_uuid` and serials requires root — implement a tiny privileged helper or `AmbientCapabilities`/udev rule alternative; **Default:** run a one-shot root-owned evidence collector at install/boot (`ExecStartPre=` helper that writes a root-written, agent-readable `evidence_cache.json` with `0640`), and document it.
2. `installers/windows/install.ps1` + `service_wrapper.py` (pywin32 `win32serviceutil`), installs to `C:\ProgramData\VenueDesk`, ACL-restricted state dir, runs as `LocalService`/virtual service account where feasible.
3. Backend `Dockerfile`, `docker-compose.yml` (postgres, backend via gunicorn), `.env.example`, production config enforcing `HTTPS` (honor `X-Forwarded-Proto`, set `SESSION_COOKIE_SECURE`, `HSTS` header). Agent **refuses `http://` server URLs** unless `allow_insecure_dev = true` (dev only; log a loud warning).
4. Logging: structured JSON logs, token/secret redaction filter (unit tested).
5. `docs/RUNBOOK.md`: install, enroll, verify, move lab, replace GPU/SSD/mobo, reinstall OS, dual-boot, rotate credential, revoke device, golden-image procedure (§27: image contains **agent software only**; unique key generated at first boot), backup/restore, retention.
6. `docs/THREAT_MODEL.md` (spec §69 threats ↔ controls table).
**Exit:** `docker compose up` brings the backend up; `shellcheck`/PowerShell syntax check pass if tools available; CI workflow green locally via `act` or equivalent dry-run (skip if unavailable and note in DECISIONS).

### Phase 12 — Full end-to-end validation
Write `tests/e2e/test_full_lifecycle.py` that boots the Flask app in-process and drives fake endpoints through: create asset → pairing token → enroll → verify → heartbeat/telemetry → IP/hostname/GPU/SSD change → OS reinstall recovery → dual-boot second OS → mobo replacement → clone/duplicate detection → revoke. Also `tools/fake_endpoint.py --scenario all` runs the same against a live local server.
**Exit:** all pass; produce `docs/E2E_REPORT.md` summarizing scenarios and results.

---

## 7. Agent Runtime Behavior (`agent/main.py`)

CLI (argparse/click): `venuedesk-agent run | enroll | status | print-identity | recover | rotate-credential | collect-once`.

Startup (spec §49):
1. Load config → set up logging (with redaction) → open local SQLite state.
2. Load or create `agent_instance_id`.
3. Load credential (`device_id` + key). If missing → if `enroll` args present, enroll; else log "not enrolled" and exit non-zero with clear message (service mode: retry every 60 s without crash-looping).
4. Collect identity evidence; send `/identity` if fingerprint differs from last sent.
5. Loop with independent timers (single-threaded scheduler with `scheduler.py`, jittered ±10%): heartbeat (60 s), telemetry (60 s), inventory (6 h + on change), jobs poll (60 s), config refresh (on `config_version` change from heartbeat).
6. All network sends go through the **outbox**; direct send first, queue on failure.
7. Graceful shutdown on SIGTERM/service stop: flush state, close DB.
Local state table keys: `agent_instance_id, device_id, credential_version, last_heartbeat, last_inventory_hash, last_identity_fingerprint, config_version`.

Config (`config.toml`): `server_url`, `deployment_salt`, `heartbeat_seconds`, `telemetry_seconds`, `inventory_seconds`, `jobs_poll_seconds`, `outbox_max_items` (default 10000), `outbox_ttl_hours` (24), `key_store` (`file`|`tpm`), `approved_services` ([]), `diagnostic_allowlist` ([]), `allow_insecure_dev` (false), `log_level`, `state_dir`. Env var overrides with prefix `VENUEDESK_`.

---

## 8. Coding Standards & Quality Gates

- Type-annotate public functions; docstrings on services and security modules explaining the invariant they protect.
- No secrets in code; `.env.example` only. Add `.gitignore` (state dirs, `.env`, `*.db`, keys).
- All time handling in UTC; never `datetime.utcnow()` naive — use timezone-aware.
- Database writes for enrollment, recovery, approvals, token consumption are transactional.
- Input validation via marshmallow schemas on every endpoint; reject unknown fields on agent endpoints; max body size 2 MB (telemetry batches 500 samples).
- Constant-time comparison for any secret-derived values.
- Coverage targets: `security/` ≥ 95%, `identity_service` ≥ 90%, overall ≥ 80%.
- `ruff check` and `ruff format --check` must pass; `mypy` errors allowed only with inline `# type: ignore[...]` + reason.

---

## 9. Example Code Anchors (implement these exact semantics)

```python
# security/signatures.py
import hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def canonical_string(method: str, path_with_query: str, ts: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path_with_query, ts, nonce, body_hash]).encode()

def verify(pub_b64: str, sig_b64: str, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except (InvalidSignature, ValueError):
        return False
```

```python
# identity/fingerprint.py
import json, hashlib, hmac
PLACEHOLDERS = {"", "none", "unknown", "default string", "to be filled by o.e.m.", "not specified", "0"}
def norm(v):
    if v is None: return None
    s = " ".join(str(v).strip().lower().split())
    if s in PLACEHOLDERS or set(s) <= {"0", "-"} or set(s) <= {"f", "-"}: return None
    return s
def norm_list(items): return sorted({n for n in map(norm, items or []) if n})
def fingerprint(ev: dict, version: int = 1) -> str:
    canon = {"v": version, "machine_uuid": norm(ev.get("machine_uuid")), "bios_serial": norm(ev.get("bios_serial")),
             "motherboard_serial": norm(ev.get("motherboard_serial")), "cpu": norm(ev.get("cpu")),
             "gpus": norm_list(ev.get("gpus")), "disks": norm_list(ev.get("disks")), "nics": norm_list(ev.get("nics"))}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def field_hash(salt: bytes, value) -> str | None:
    n = norm(value)
    return hmac.new(salt, n.encode(), hashlib.sha256).hexdigest() if n else None
```

```python
# services/enrollment_service.py (outline)
def enroll_with_token(payload, source_ip):
    with db.session.begin():                       # one transaction
        tok = consume_token_atomically(payload["enrollment_token"])   # raises if invalid/expired/used/revoked
        verify_proof_of_possession(payload)
        device = PhysicalDevice(device_id=new_device_id(), device_public_key=payload["device_public_key"],
                                status="PENDING_VERIFICATION", credential_version=1, ...)
        link = AssetDeviceLink(asset_id=tok.asset_id, device=device, relationship_status="ACTIVE", linked_by="system",
                               reason="asset-scoped enrollment token")
        add_evidence_snapshot(device, payload["identity_evidence"], trusted=False)
        upsert_os_installation(device, payload["os"], payload["agent_instance_id"])
        upsert_inventory(device, payload["inventory"])
        asset_mark_pending_verification(tok.asset_id)
        audit("DEVICE_ENROLLED", ...); audit("DEVICE_LINKED", ...)
    return enrollment_response(device, tok.asset)
```

---

## 10. Definition of Done (all must be true)

- [ ] All 12 phases complete; every Exit Criteria satisfied; commits per phase exist.
- [ ] `pytest -q` passes for backend, agent, and e2e; coverage targets met.
- [ ] All spec acceptance tests (§66) exist as named tests and pass, plus the extra tests in Phase 7.
- [ ] Two near-identical fake endpoints map to **different** assets via different tokens; a high similarity score never links an asset.
- [ ] Dual-boot modeled as one PhysicalDevice + multiple OSInstallation rows; OS count is derived.
- [ ] OS reinstall → recovery/re-verification, never a new Asset.
- [ ] Motherboard/TPM change → HIGH identity-change event + strong verification workflow.
- [ ] Golden-image safety verified by test (no key/device ID baked in; first boot generates unique identity).
- [ ] Signed requests, replay protection, rotation, revocation all working and tested.
- [ ] Remote jobs allowlisted; no `shell=True` in the agent; test enforces it.
- [ ] Admin UI pages from Phase 10 working with RBAC + CSRF; raw pairing token shown once only.
- [ ] Offline outbox verified; priority-0 items never dropped before TTL.
- [ ] Linux systemd + Windows service installers, Dockerfile, docker-compose, CI workflow, `.env.example`, `config.example.toml` present.
- [ ] Docs complete: `README.md`, `ARCHITECTURE.md`, `API.md`, `RUNBOOK.md`, `THREAT_MODEL.md`, `DECISIONS.md`, `E2E_REPORT.md`.
- [ ] README has a 10-minute quickstart: `docker compose up` → create asset → copy token → `venuedesk-agent enroll` → see device live in UI.

---

## 11. Known Limitations to Document (be honest in README/RUNBOOK)

- Default key storage is software-based (OS-protected file / DPAPI); TPM-backed keys are behind the `TpmKeyStore` interface and not enabled by default. A TPM-backed key is strong continuity evidence, not an absolute guarantee.
- Some hardware identifiers (DMI serials, system UUID) require elevated privileges on Linux and may be missing or placeholder values on some OEM/virtual hardware; the system degrades to weaker evidence and routes to manual verification rather than guessing.
- Motherboard/TPM replacement is intentionally a manual, audited workflow.
- Scoring weights are illustrative defaults and configurable; they are advisory only.

---

## 12. Suggested First Commands

```bash
mkdir venuedesk && cd venuedesk && git init
# Phase 0: scaffold per Section 2
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e "./venuedesk-backend[dev]" -e "./venuedesk-agent[dev]"
pytest -q
```

Begin with Phase 0. After each phase, append a short note to `docs/DECISIONS.md` and proceed automatically to the next.
