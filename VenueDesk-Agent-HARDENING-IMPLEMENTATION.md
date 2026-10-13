# VenueDesk-Agent — Identity Hardening & Production Readiness: Implementation Instructions

> **Audience:** an autonomous AI coding agent (Antigravity / CLI agent).
> **Mission:** take the *existing* repository `VenueDesk-Agent` (monorepo with `venuedesk-backend/`, `venuedesk-agent/`, `tests/e2e/`, `tools/`, `docs/`, `.github/workflows/`) from a working prototype to a reliable, secure, auditable asset-management system that a college could deploy on hundreds of computers.
> **Companion spec:** `VenueDesk-Agent-Identity-and-Asset-Mapping-Technical-Specification.md` (identity semantics). If this file and the spec conflict on identity semantics, the spec wins; on implementation detail, this file wins.
> **Important:** the author of this plan has not run the repository. Every file path and function name below is an *implementation target to verify against the current branch*. If a name differs, find the real equivalent, use it, and note it in `docs/DECISIONS.md`.

---

## 0. Operating Rules (read first, obey always)

1. **Do not ask the user questions.** When ambiguous, take the option marked **Default**, implement it, and append a row to `docs/DECISIONS.md` (`date | phase | decision | reason`).
2. **Existing code is the source of truth for conventions.** Reuse existing models, session handling, service layout, error shapes, test fixtures and naming. Do not rewrite working modules; change the minimum needed, and add tests first for each fix (**test-first for every bug**: write the failing test, watch it fail, fix, watch it pass).
3. **Work phase by phase, in order.** Do not start a phase until the previous phase's *Exit Criteria* hold. After each phase: `ruff check`, `pytest -q` (all suites), commit with message `phase-N: <title>`.
4. **Never mask a failure.** Do not delete, skip (`xfail`/`skip`) or weaken an existing test to make the suite green. If an existing test encodes a wrong behavior, change it deliberately and record why in `DECISIONS.md`.
5. **Do not fix unrelated errors in Phase 0.** Record them in the baseline report.
6. **Security invariants (never violate):**
   - Asset ID, Device ID and OS-installation identity stay separate. A hardware fingerprint, hostname, IP, MAC, OS machine-id, CPU/GPU model or similarity score is **never** sufficient on its own to link an asset to a device.
   - Raw pairing tokens, private keys, signatures and full hardware serials never appear in logs, audit rows, API error bodies, or the database (tokens stored hashed only).
   - Every API endpoint has an **explicit** authorization policy; an endpoint without one must fail closed.
   - Remote jobs stay allowlisted; no `shell=True`.
   - Audit log is append-only.
7. **All time handling is timezone-aware UTC.**
8. **Be honest in docs.** Document limitations (e.g., TPM not enabled by default, privilege requirements for DMI serials on Linux).
9. **Test data is synthetic.** No real credentials, serials, or production hardware IDs in fixtures.

---

## 1. Branch, Environment, Commands

```bash
git checkout -b improvement/identity-hardening

python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate

pip install -e "./venuedesk-backend[dev]" -e "./venuedesk-agent[dev]"
pytest -q
```

Useful additions (install in dev extras if missing): `pytest-cov`, `pytest-xdist` (optional), `ruff`, `mypy`, `pip-audit`, `bandit`, `freezegun` (or equivalent), `pytest-timeout`.

PostgreSQL for concurrency tests: provide a `docker-compose.test.yml` with a `postgres:16` service; tests marked `@pytest.mark.postgres` read `TEST_DATABASE_URL` and are **skipped locally when it is unset** but **always run in CI** (CI provides a postgres service container). Everything else must pass on SQLite.

---

# Phase 0 — Establish a Reliable Baseline

**Priority P0 · Goal:** know exactly what works before changing identity logic.

### Tasks
1. Run the existing tests unmodified in a clean venv. Save raw output to `docs/baseline/pytest_baseline.txt`.
2. Generate `docs/baseline/BASELINE.md` containing:
   - Pass/fail/skip/error counts per suite (backend, agent, e2e) and a list of each failing test with the failure reason (tag each as `code-bug`, `env-dependent`, or `flaky`).
   - Current API endpoints: script it — iterate `app.url_map.iter_rules()` and write a table `method | path | auth decorator found? | roles`. Save script as `tools/dump_routes.py`.
   - Current DB models and relationships: script `tools/dump_models.py` that prints each table, columns, FKs, unique constraints, indexes (via SQLAlchemy inspector). Save output.
   - Where each concern lives: enrollment, pairing (`pair_unclaimed_device`), identity reconciliation, authentication (`signatures.py`), nonce/replay, token consumption, OS-installation upsert, outbox, jobs.
   - Existing identity-related tests (list names).
   - Known bugs / missing tests discovered while reading (be specific: file, line range, why).
3. Confirm reproducibility: a second clean-venv run yields the same pass/fail counts.

### Exit criteria
- `docs/baseline/BASELINE.md`, route dump, model dump and raw pytest output committed.
- Baseline reproducible on a clean checkout.
- **No source changes in this phase** except the two `tools/dump_*.py` scripts.

---

# Phase 1 — Fix Device-to-Asset Mapping

**Priority P0 · Primary files:** `venuedesk-backend/app/services/identity_service.py`, link model (`AssetDeviceLink` or equivalent), migrations.

### Relationship rules (implement exactly)
| Rule | Required behavior |
|---|---|
| One physical device | ≤ 1 **ACTIVE** asset link |
| One asset | ≤ 1 **ACTIVE** device link (**Default**; one flag `ALLOW_MULTI_DEVICE_ASSET=false` documents the assumption) |
| Reassignment | Close the old link (`relationship_status=CLOSED`, `unlinked_at`, `reason`) before creating the new one, in the **same transaction** |
| Replacement computer | New device registered; old device history preserved; old link CLOSED |
| Ambiguous identity | Reject with `needs_verification`; never auto-relink |

### Tasks
1. **Reproduce first.** Write tests (below) against the current code. Record which ones fail in `DECISIONS.md` (this documents the real bug).
2. **Rewrite `pair_device` (wrap/replace `pair_unclaimed_device`)** with this algorithm, in one transaction:
   1. Load asset and device with row locks (`with_for_update()` on PostgreSQL; on SQLite rely on `BEGIN IMMEDIATE` — set `isolation_level`/event hook so write transactions take the write lock up front).
   2. Validate: asset exists and `lifecycle_status` permits pairing (not RETIRED/DISPOSED); device exists and `status` permits pairing (UNCLAIMED, PENDING_REVERIFICATION by explicit admin action; not REVOKED/RETIRED).
   3. Look up ACTIVE link for the asset and for the device.
   4. If either exists and the call lacks an explicit `reassignment=True` + `reason` + authorized actor with role `infra_admin` → raise `LinkConflictError` (HTTP 409 `link_conflict`, no information about *which* other asset/device).
   5. If reassignment is authorized: close the old link(s), emit audit `DEVICE_UNLINKED`.
   6. Create the new ACTIVE link, set device status → `PENDING_VERIFICATION`, asset → `PENDING_VERIFICATION`, emit audit `DEVICE_LINKED` with old/new values.
   7. Commit; on any exception roll back so the DB is unchanged.
3. **Database protection (mandatory, not optional):** new Alembic migration adding
   - partial unique index `uq_active_link_per_asset` on `asset_device_links(asset_id) WHERE relationship_status='ACTIVE'`
   - partial unique index `uq_active_link_per_device` on `asset_device_links(device_id) WHERE relationship_status='ACTIVE'`
   Use `sqlalchemy.Index(..., unique=True, postgresql_where=..., sqlite_where=...)` — both PostgreSQL and SQLite support partial unique indexes. Before applying, the migration must detect existing duplicate ACTIVE links and **fail with a clear message** listing offenders (add `tools/find_duplicate_links.py` and document the cleanup procedure in `docs/RUNBOOK.md`). Also add the same checks to model `__table_args__` so `create_all()` in tests produces the constraints.
4. Catch `IntegrityError` from the constraints in the service and translate to `LinkConflictError` (this is the race-condition backstop).
5. Apply the same checks to the **token-based enrollment path** (it also creates links) and to any admin "verify/replace endpoint" path — grep for every place that constructs a link object; all must go through one function.

### Required tests (`venuedesk-backend/tests/test_pairing_integrity.py`)
- `test_device_already_linked_cannot_link_to_second_asset`
- `test_asset_already_linked_cannot_accept_second_device`
- `test_authorized_replacement_closes_old_link_and_preserves_history`
- `test_unauthorized_reassignment_rejected` (non-admin or missing reason)
- `test_failed_pairing_leaves_database_unchanged` (inject a failure mid-transaction; assert row counts/state identical)
- `test_concurrent_pairing_same_asset` (≥ 8 threads, file-based SQLite *and* `@pytest.mark.postgres`): exactly one succeeds, others get conflict, DB has exactly one ACTIVE link
- `test_concurrent_pairing_same_device_two_assets`
- `test_token_enrollment_respects_link_rules`
- `test_db_rejects_duplicate_active_link_even_if_service_bypassed` (insert directly via SQL)

### Exit criteria
Every test above passes; no code path outside `pair_device` creates links (verified by a test that greps the app package for direct `AssetDeviceLink(` construction outside the allowed module).

---

# Phase 2 — Harden Authentication & Authorization

**Priority P0 · Primary files:** `venuedesk-backend/app/security/signatures.py`, `security/replay.py`, `security/tokens.py`, `api/*.py`.

### Step 1 — Explicit per-endpoint, per-state policy (fail closed)
Create `app/security/policy.py` with a **single registry**:

```python
ENDPOINT_POLICY = {
    # endpoint (blueprint.func)       auth kind            allowed device states / roles
    "agents.enroll": Policy(auth="token_or_unclaimed_flag", rate_limit="10/min"),
    "agents.recover": Policy(auth="none+evidence", rate_limit="10/min"),
    "agents.heartbeat": Policy(
        auth="device",
        states={ACTIVE, OFFLINE, PENDING_VERIFICATION, PENDING_REVERIFICATION},
    ),
    "agents.telemetry": Policy(auth="device", states={ACTIVE, OFFLINE}),
    "agents.inventory": Policy(
        auth="device",
        states={ACTIVE, OFFLINE, PENDING_VERIFICATION, PENDING_REVERIFICATION},
    ),
    "agents.identity": Policy(
        auth="device",
        states={ACTIVE, OFFLINE, PENDING_VERIFICATION, PENDING_REVERIFICATION},
    ),
    "agents.config": Policy(
        auth="device",
        states={ACTIVE, OFFLINE, PENDING_VERIFICATION, PENDING_REVERIFICATION},
    ),
    "agents.jobs": Policy(auth="device", states={ACTIVE}),
    "agents.job_result": Policy(auth="device", states={ACTIVE}),
    "agents.rotate": Policy(auth="device", states={ACTIVE, PENDING_REVERIFICATION}),
    "agents.recover_status": Policy(auth="device", states={PENDING_REVERIFICATION}),
    # admin endpoints: auth="session", roles={"infra_admin"} or {"infra_admin","infra_viewer"}
}
```
Resulting matrix (**Default**; adjust only via this one file):

| Device state | Heartbeat | Inventory/identity | Telemetry | Jobs | Enroll/recover |
|---|---|---|---|---|---|
| UNCLAIMED | deny | deny | deny | deny | enroll/pairing flow only |
| PENDING_VERIFICATION | allow | allow (needed for verification evidence) | deny | deny | – |
| ACTIVE / OFFLINE | allow | allow | allow | allow (ACTIVE) | – |
| PENDING_REVERIFICATION | allow | allow | deny | deny | recovery/verification flow only |
| SUSPENDED | deny | deny | deny | deny | admin-authorized recovery only |
| REVOKED | deny | deny | deny | deny | new registration with new token only |
| RETIRED | deny | deny | deny | deny | admin operations only |

Denied-by-state responses: `403 {"error":"device_blocked"}` with no state detail. **Fail-closed test:** `test_every_route_has_policy` iterates `app.url_map` and fails if any `/api/` route (except `/healthz`) is missing from `ENDPOINT_POLICY`. The decorator `@enforce_policy` reads the registry; endpoints must not hand-roll state checks.

### Step 2 — Correct verification order and atomic replay protection
Request pipeline (in this order, each failure returns the generic `401 {"error":"unauthorized"}` and logs the *specific* internal reason without secrets):
1. Validate required headers/structure (`X-Device-ID`, `X-Timestamp`, `X-Nonce`, `X-Key-Version`, `X-Signature`), max body size.
2. Validate timestamp within `CLOCK_SKEW_SECONDS` (default 120).
3. Load device, check key version.
4. Verify Ed25519 signature over `METHOD\nPATH_WITH_QUERY\nTS\nNONCE\nsha256_hex(raw_body)` (raw bytes; no re-serialization of JSON).
5. **Atomically** consume the nonce: `INSERT` into `request_nonces` with unique `(device_id, nonce)`; `IntegrityError` ⇒ replay ⇒ reject. (Nonce is registered **only after** signature verification so unauthenticated callers cannot fill the table.) Do not use check-then-insert.
6. Apply the state/role policy (Step 1).
7. Execute the operation.
Opportunistic purge of expired nonces on write plus `flask purge-nonces` CLI.

### Step 3 — Pairing token hardening (verify, fix if not true)
- Generated with `secrets.token_urlsafe(32)`, prefixed `PAIR-`; stored as SHA-256 only; scoped to one asset; has `expires_at`.
- Consumption is a single atomic statement: `UPDATE enrollment_tokens SET status='USED', used_at=now, used_by_device_id=:d WHERE token_hash=:h AND status='ACTIVE' AND expires_at>now AND revoked_at IS NULL` → **rows affected must be 1**, else reject. (Works identically on SQLite and PostgreSQL; no reliance on `FOR UPDATE`.)
- Token failure (bad proof-of-possession, schema error after consumption) must follow documented policy: **Default — a token is consumed only if the whole enrollment transaction commits**; consumption and device creation happen in the same transaction, so a failed enrollment leaves the token ACTIVE. Document this in `docs/API.md`.
- Add a logging filter (`app/logging_filters.py`) redacting `PAIR-…` patterns, `X-Signature`, and base64 blobs > 40 chars in keys named `*token*|*key*|*secret*|*signature*`. Unit-test it. Add a test that enrolls with a token with log capture enabled and asserts the raw token never appears in any captured log record, audit row, or response body other than the one-time admin display.
- Errors reveal nothing about which assets/devices exist: all token failures → `400 {"error":"invalid_enrollment_token"}`.

### Required tests (`tests/security/`)
`test_invalid_signature`, `test_tampered_body`, `test_tampered_path_or_method`, `test_expired_timestamp`, `test_future_timestamp`, `test_replayed_nonce`, `test_concurrent_same_nonce_exactly_one_wins` (threads, 2 DB backends), `test_revoked_device_telemetry_denied`, `test_unclaimed_device_jobs_denied`, `test_pending_device_cannot_send_telemetry`, `test_suspended_device_denied_everything`, `test_expired_token`, `test_reused_token`, `test_revoked_token`, `test_token_for_asset_a_cannot_enroll_as_asset_b`, `test_concurrent_token_use_exactly_one_wins`, `test_token_never_in_logs`, `test_every_route_has_policy`, `test_policy_matrix` (parametrized over the table above — state × endpoint → expected status).

### Exit criteria
Every endpoint has an explicit policy; all negative tests pass on SQLite and PostgreSQL.

---

# Phase 3 — Reliable Identity Reconciliation

**Priority P0 · Primary files:** `venuedesk-backend/app/services/identity_service.py`, `venuedesk-agent/agent/identity/fingerprint.py`, `agent/identity/reconciliation.py`.

### Principles (encode as module docstrings and tests)
- Device ID, registered public key, hostname, IP, RAM/GPU inventory, fingerprint and OS installation ID have different roles (see table in the spec §2). **Fingerprint mismatch alone never creates a new device and never relinks an asset.**
- Key rotation alone never creates a new device.

### Tasks
1. **Fingerprint versioning explicit.** Ensure `fingerprint_version` is stored with every snapshot; `fingerprint()` takes a `version` parameter and dispatches to `_fingerprint_v1`, `_fingerprint_v2`… Never edit a released version's behavior; add a new version. Server compares fingerprints **only within the same version**; for different versions it recomputes comparison from stored per-field hashes rather than comparing hash values.
2. **Missing evidence handling.** Normalization maps placeholder values (`""`, `none`, `unknown`, `default string`, `to be filled by o.e.m.`, all-zeros/all-F UUIDs, etc.) to `None`. **`None == None` is never evidence of sameness**: comparison functions return a tri-state per field `MATCH | MISMATCH | UNKNOWN`; `UNKNOWN` contributes nothing to similarity and never counts toward "strong anchors match". Unit-test that two machines with all serials missing are never "the same".
3. **Change classification** (`classify_change(prev_trusted, current) -> list[ChangeRecord]` + overall `ReconciliationDecision`):

| Observation | Action | Needs admin approval? |
|---|---|---|
| IP changed | update inventory, event `IP_CHANGED` (LOW) | no |
| Hostname changed | update inventory, event `HOSTNAME_CHANGED` (LOW) | no |
| RAM / GPU changed | `HARDWARE_CHANGED` + `RAM_CHANGED`/`GPU_CHANGED` (LOW) | no |
| Disk / NIC set changed | `DISK_CHANGED`/`NIC_CHANGED` (MEDIUM) | no (flag for review if combined with others) |
| Fingerprint algorithm upgraded | controlled migration: recompute from field hashes, store new snapshot with new version, event `FINGERPRINT_MIGRATED` (INFO) | no |
| ≥ 2 strong anchors conflict (machine UUID, motherboard, BIOS, TPM) | `IDENTITY_CHANGE_DETECTED` (HIGH); device → `PENDING_REVERIFICATION` | **yes** |
| Credentials lost (new key, same hardware) | enter recovery flow (Phase 4) | **yes** |
| New machine with similar specs, no token / no credential | do **not** pair automatically; `UNCLAIMED` or `MANUAL_VERIFICATION` | yes |

   Severity map is config-driven (`IDENTITY_SEVERITY_POLICY`). The similarity score (if kept) only **ranks candidates for human review**; assert with a test that no code path links an asset based on a score.
4. **Preserve historical evidence.** Evidence snapshots are append-only (`trusted` flag flips only through an approval action). Add table **`hardware_change_records`**: `id, device_id, occurred_at, field, previous_value (hashed/redacted), new_value (hashed/redacted), evidence_source (AGENT_INVENTORY|AGENT_IDENTITY|ADMIN|RECOVERY), reconciliation_decision, requires_approval (bool), approved_by, approved_at, audit_log_id`. Keep `device_inventory` as the separate "latest state" table for dashboards. Migration required.
5. Agent side: `reconciliation.py` should detect local change (compare against last-sent fingerprint/hash) and trigger an immediate `/identity` or `/inventory` send rather than waiting for the next interval.

### Required tests (`tests/identity/`)
`test_ip_change`, `test_hostname_change`, `test_ram_change`, `test_gpu_change`, `test_disk_replacement`, `test_motherboard_evidence_change_alone_requires_review`, `test_missing_serial_never_equals_missing_serial`, `test_fingerprint_version_migration_preserves_identity`, `test_fingerprint_unchanged_for_released_version` (golden-vector test: fixed input → fixed v1 hash, so accidental changes fail CI), `test_conflicting_strong_evidence_enters_pending_reverification`, `test_identical_hardware_new_machine_not_auto_paired`, `test_similarity_score_never_links_asset`, `test_history_retained_after_each_change`, `test_key_rotation_does_not_create_new_device`.

### Exit criteria
Normal changes update inventory without touching the registered identity; ambiguous changes produce a review state, never a silent reassignment; golden-vector test pins fingerprint v1.

---

# Phase 4 — Dual Boot, Reinstall, and Recovery

**Priority P0 · Primary files:** OS-installation model + upsert logic in `identity_service.py`, agent `identity/device_id.py`, enrollment/recovery endpoints.

### Target model
```
Asset ── (1 ACTIVE link) ── PhysicalDevice ──┬── OSInstallation (Windows)
                                              └── OSInstallation (Linux)
```
OS count is derived, never stored.

### Tasks
1. **Fix OS-installation identification.** Search for any code selecting "the first/any active installation" for a device (`.first()`, `[0]` on OS rows). Replace with lookup by **`(device_id, os_installation_id)`**. Every agent report (heartbeat, inventory, identity, telemetry) must include `os_installation_id` (agent-generated: UUIDv4 created once per OS install and stored in the OS-local state dir) plus the existing `os_machine_id_hash` and `agent_instance_id`. Migration: add `os_installation_id` (unique per device); backfill existing rows from `agent_instance_id`.
2. **Unknown installation id from an authenticated, ACTIVE device** (valid signature by the device key ⇒ same device keypair): create a new `OSInstallation` (first_seen, status ACTIVE), event `OS_INSTALLATION_ADDED`. **Dual boot caveat:** each OS has its own filesystem and therefore its own agent state/key. Handle the two cases explicitly:
   - **Shared credential case** (key copied to a shared partition/enrolled by the admin): reports are signed by the same key → same device → new OS installation row.
   - **Separate credential case (Default)**: second OS runs its own agent with its own key; it must be enrolled via **"add OS installation to existing device"** — an admin-created, device-scoped, single-use, short-lived *OS-enrollment token* (new table column `enrollment_tokens.scope = ASSET|DEVICE`, plus `device_id` for DEVICE scope). Presenting it from the second OS registers the new public key as an *additional credential* for the same PhysicalDevice (new table `device_credentials`: `device_id, os_installation_id, public_key, credential_version, status, created_at, revoked_at`; migrate existing `physical_devices.device_public_key` into it). Signature verification looks up the key by `(device_id, key fingerprint/os_installation_id)`. Evidence must be consistent with the existing device's strong anchors; otherwise → `PENDING_REVERIFICATION`.
3. **Recovery workflow** (agent lost its key, e.g., after reinstall):
   1. Old device record and its history remain.
   2. New install generates a new key and calls `POST /api/v1/agents/recover` with evidence (no token).
   3. Server **never** lets it claim the old identity from similarity alone. It creates a `recovery_requests` row (`id, candidate_device_id (nullable), evidence_snapshot_id, status PENDING|APPROVED|REJECTED|EXPIRED, created_at, decided_by, decided_at, reason`) and sets state per policy (candidate device → `PENDING_REVERIFICATION`; unknown → `UNCLAIMED`). Event `OS_REINSTALL_DETECTED`.
   4. Admin verifies physically and approves with a reason **or** issues a fresh device-scoped re-pairing token.
   5. On approval: server registers the new public key as the active credential for that OSInstallation's slot, bumps `credential_version`, marks the previous credential `REVOKED` (where appropriate), marks the old `OSInstallation` HISTORICAL and creates the new ACTIVE one.
   6. Audit `CREDENTIAL_ROTATED` / `HARDWARE_CHANGE_APPROVED` with actor and reason.
   If the previous credential is still available, the simpler authenticated `POST /agents/rotate-credential` (new key signed by old key) applies — no admin needed.
4. Agent: `agent recover` CLI command; on startup, if state/key missing but `server_url` configured and **no token** provided, log a clear message and wait in "awaiting recovery" mode polling `/recover/status` (bounded backoff) — not crash-looping.

### Required tests (`tests/e2e/test_dual_boot_recovery.py`) — the full sequence
1. Enroll physical computer (asset token).
2. Report Windows inventory (os_installation_id W1).
3. Enroll Linux via device-scoped OS token; report Linux inventory (L1) — same `device_id`, same asset link, two ACTIVE OSInstallations.
4. Windows reports again → still W1, not "first row".
5. Reinstall Linux → new key, new os_installation_id L2, recovery request created; asset/device link unchanged; no new Asset/Device created.
6. Without approval the L2 agent is denied jobs/telemetry.
7. Admin approves → L2 ACTIVE, L1 HISTORICAL, old credential revoked, `credential_version` incremented, audit rows present.
Plus: `test_ambiguous_candidates_require_manual_pairing`, `test_recovery_never_uses_similarity_alone`, `test_device_scoped_token_cannot_be_used_for_other_device`, `test_os_count_is_derived`.

### Exit criteria
One physical device and correct asset link persist throughout dual boot / reinstall / recovery; OS installations tracked independently; every step audited.

---

# Phase 5 — Reliable Offline Operation

**Priority P1 · Primary files:** `venuedesk-agent/agent/storage/outbox.py`, `communication/retry.py`, backend ingestion endpoints.

### Tasks
1. **Event lifecycle in the outbox table:** columns `event_id (uuid4, PK)`, `kind`, `priority (0 identity/events, 1 inventory, 2 telemetry)`, `payload (JSON)`, `created_at`, `status (PENDING|IN_FLIGHT|DELIVERED|FAILED_PERMANENT)`, `attempts`, `next_attempt_at`, `last_error (redacted)`. Lifecycle: generated → saved (committed transaction) → waiting → sent → **acknowledged** → DELIVERED → purged after retention. An HTTP attempt never deletes an event; only a server ACK does. On startup, any `IN_FLIGHT` row older than a threshold reverts to `PENDING` (crash recovery).
2. **Retries:** bounded exponential backoff with full jitter (base 2 s, cap 5 min, configurable), honor `Retry-After`. Classification: network errors, 5xx, 429, 408 → transient (retry); 400/422 → `FAILED_PERMANENT` (log + keep for diagnostics, bounded); 401 → try one credential-state check (key version mismatch → fetch config / trigger rotation flow), else retry later; 403 `device_blocked` → pause sending (long sleep), keep queue; 404/410 on a job → drop.
3. **Server-side idempotency:** every event/batch carries `event_id`s. New table `processed_events(device_id, event_id, processed_at)` with unique `(device_id, event_id)`; ingestion inserts first and treats `IntegrityError` as "already processed → return ACK without side effects" (telemetry batch: per-sample `event_id`, dedupe; inventory/identity: reconciliation is only run for new event ids). ACK response lists accepted + duplicate ids so the agent can mark them delivered. Purge `processed_events` older than the outbox TTL + margin.
4. **Queue protection:** SQLite WAL mode, `synchronous=NORMAL` (or FULL for priority-0), all writes transactional; max items (default 10 000) and max bytes; when full, drop lowest-priority oldest **telemetry** first, never priority-0 before TTL; counters of dropped events reported in next heartbeat. Corrupt DB → move aside as `outbox.corrupt.<ts>`, create a fresh DB, emit a local event `OUTBOX_RESET`. Disk-full → degrade to in-memory minimal queue for priority-0 only, log warning. Secrets are never logged.
5. Credential rotation mid-outage: queued events are signed **at send time**, not at enqueue time (never persist signatures), so rotation doesn't strand the queue.

### Required tests (`venuedesk-agent/tests/test_outbox_*.py`, `tests/e2e/test_offline.py`)
`test_network_down_events_queued`, `test_kill_process_then_restart_preserves_queue` (subprocess + SIGKILL / terminate), `test_in_flight_reverted_after_crash`, `test_long_outage_then_drain_in_priority_order`, `test_ack_lost_duplicate_delivery_has_no_side_effects`, `test_server_dedupes_event_ids`, `test_permanent_error_not_retried_forever`, `test_expired_credentials_pause_and_recover`, `test_queue_capacity_drops_lowest_priority_first`, `test_priority0_never_dropped_before_ttl`, `test_corrupt_db_recovers`, `test_backoff_has_jitter_and_cap`, `test_no_secrets_in_agent_logs`.

### Exit criteria
No acknowledged event is processed twice; queued events survive restart and recover from connectivity loss.

---

# Phase 6 — Comprehensive Tests & CI

**Priority P0**

### Tasks
1. **Layout:** `tests/unit` (fingerprint, signatures, policy, classification), `tests/integration` (endpoints, transactions, token consumption, rotation, audit), `tests/e2e` (enroll → pair → inventory → change → final DB state). Markers: `unit`, `integration`, `e2e`, `postgres`, `slow`. Configure in `pyproject.toml`.
2. **Shared fixtures** (`tests/fixtures/` or `conftest.py`), all synthetic:
   - `ai_lab_pc_07` → `VD-ASSET-000421`, `cse_lab_pc_12` → `VD-ASSET-000422`
   - `identical_hardware_pair` (same CPU/board model/BIOS version/GPU/disk model; different serials/UUIDs, **and** a variant with missing serials)
   - `device_missing_serials`
   - `dual_os_device` (two OSInstallations)
   - `revoked_device`
   - `offline_agent_with_queue`
   - `fake_endpoint` factory reusing `tools/fake_endpoint.py` logic (real Ed25519 signing, in-process Flask test client or live server)
3. **CI (`.github/workflows/`)** — inspect existing workflows and make sure they run, as separate jobs that must all pass: (a) backend unit+integration (SQLite) on ubuntu; (b) backend `postgres` marker with a `postgres:16` service container; (c) agent tests on **ubuntu and windows**; (d) e2e; (e) `ruff check`, `ruff format --check`, `mypy` (lenient); (f) `pip-audit` and `bandit -r` on both packages (fail on high severity; allowlist with justification file `security/allowlist.md`); (g) coverage upload as artifact. Add a job step that fails if any test is skipped unexpectedly (`-rs` output check, allowing only the documented `postgres`-unset skips when run outside CI). Branch protection note in `docs/RUNBOOK.md`.
4. **Coverage priority** (enforce with `--cov-fail-under` per package, via `coverage` config): `security/` ≥ 95%, `identity_service` ≥ 90%, pairing/recovery/audit modules ≥ 90%, overall ≥ 80%. Do not chase the global number at the expense of these.
5. **Audit-log tests:** every state-changing admin/service action produces exactly one audit row with correct actor/action/entity and old/new values; audit model exposes no update/delete (test that service layer has none and that attempting `UPDATE`/`DELETE` through the ORM models raises via a SQLAlchemy event guard).

### Exit criteria
A clean checkout runs all required suites in CI, including every scenario from Phases 1–5; CI fails when any suite fails.

---

# Phase 7 — Administrator Experience

**Priority P1 · Primary files:** `venuedesk-backend/app/templates/infrastructure/*`, `api/admin_infra.py`, `services/*`.

Build server-rendered pages (reuse the app's base layout; Bootstrap 5; minimal JS). Every action: backend RBAC check (`infra_admin` for mutations, `infra_viewer` read-only), CSRF protection, audit row with actor + reason, confirmation step (typed asset tag or checkbox + reason text) for **reassign, suspend, revoke, retire, recovery approval, hardware-change approval**.

| Page | Content / actions |
|---|---|
| **Device inventory** | table: asset ID/tag, device ID, hostname, department/room, OS list, last seen (relative + absolute), status badge, hardware-change indicator; filters: lab/room, department, status, online/offline, needs-review; pagination (`per_page ≤ 100`), server-side sort, CSV export (no secrets) |
| **Enrollment & pairing** | select asset → generate short-lived pairing token (raw shown **once** in a modal with copy button, install command snippet, expiry countdown, optional QR of the token); token list with status (ACTIVE/USED/EXPIRED/REVOKED, never raw); enrollment outcome shown live (polling) |
| **Change history** | per device: previous vs current value (redacted/hashed where sensitive), time, source, decision, whether auto-accepted or needed approval, approver |
| **Verification queue** | devices in `PENDING_VERIFICATION`/`PENDING_REVERIFICATION`/UNCLAIMED + recovery requests: reason, supporting evidence summary (which anchors match/mismatch — masked), available actions (Verify, Approve change, Approve recovery, Reject, Suspend, Pair to asset) |
| **Device detail** | asset block, device block, hardware, current telemetry (Chart.js), OS installations, events, jobs, audit slice, credential versions |
| **Lifecycle actions** | enroll, verify, suspend/unsuspend, reassign (close/create link), retire, rotate credential, revoke |
| **Audit log** | filter by actor, action, entity, date; pagination |

Display rules: never show raw secrets, private keys, tokens, or full serials (mask all but last 4 of any displayed identifier; hashes truncated).

### Tests
Route smoke (200 for admin, 403 for viewer on mutations, 302/401 for anonymous), CSRF required on POST, token shown once only (second view of same token impossible), mutation pages create audit rows, large-fleet pagination test (seed 1 000 devices; list endpoint stays within a query-count budget — assert ≤ N queries via SQLAlchemy event counter, no N+1).

### Exit criteria
An administrator can enroll, inspect, verify, suspend, and reassign devices entirely via the UI/API — no manual DB edits (prove with an e2e UI-level test).

---

# Phase 8 — Production Deployment & Operational Hardening

**Priority P1** (do only after Phases 1–6 are green)

### Step 1 — Database
- Ensure Alembic migrations exist for the *entire* current schema (generate a baseline migration if the repo relies on `create_all`); `flask db upgrade` from empty must work on SQLite and PostgreSQL; add `tools/test_migration_on_copy.py` that copies a dev DB, upgrades, and runs integrity checks (no duplicate ACTIVE links, FK integrity).
- Production default: **PostgreSQL** (`DATABASE_URL`); SQLite supported for dev only (config refuses SQLite when `ENV=production` unless `ALLOW_SQLITE_PROD=true`).
- Indexes: `(device_id, timestamp)` on telemetry; `(device_id, occurred_at)` on events; `(status, last_seen)` on devices; `(asset_id, relationship_status)` on links.
- Docs: backup/restore procedure (`pg_dump`/`pg_restore` commands), tested via a script `tools/backup_restore_check.sh`. Retention CLI: `flask purge-telemetry --older-than-days N`, `purge-nonces`, `purge-processed-events`.

### Step 2 — Server configuration
Separate `Development/Testing/Production` config classes; production **requires** `SECRET_KEY`, `DEPLOYMENT_SALT`, `DATABASE_URL` (app refuses to start otherwise); HTTPS enforcement (`X-Forwarded-Proto` handling via `ProxyFix` with configured trusted hops, HSTS, secure cookies); `MAX_CONTENT_LENGTH` 2 MB; rate limits (Flask-Limiter with storage URL, Redis optional; in-memory fallback documented as single-process only) on enroll/recover/admin-login; centralized JSON logs with the redaction filter; DB user least-privilege notes; `gunicorn` config; `Dockerfile` + `docker-compose.yml` (backend, postgres, optional nginx/caddy TLS-terminating reverse proxy example). Credential revocation procedure documented and exercised by a test.

### Step 3 — Agent packaging
- Linux: `installers/linux/install.sh`, `uninstall.sh`, `venuedesk-agent.service` (dedicated user, `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths`, `Restart=always`); privileged evidence collection via a root-owned oneshot helper writing `0640` `evidence_cache.json` (documented).
- Windows: `installers/windows/install.ps1`, `uninstall.ps1`, service via pywin32/`win32serviceutil` (or NSSM fallback, documented), state dir ACL-restricted, runs as a low-privilege service account where feasible.
- Both: config/server-URL setup; `venuedesk-agent status` health output; agent health in heartbeat (`queue_depth`, `dropped_events`, `last_error_code`, `agent_version`); log files with rotation; **uninstall is always possible for the administrator** (documented, no tamper tricks); credential rotation and recovery steps in `RUNBOOK.md`.
- **Safe update mechanism with version tracking (Default, minimal):** agent reports `agent_version`; server config exposes `min_supported_agent_version` and `latest_agent_version` + download URL + SHA-256 + **Ed25519 release signature** (release signing key public half baked into the agent). Agent *never* auto-executes unsigned or hash-mismatched packages; **Default behavior is notify-only** (admin dashboard shows outdated agents; `update` is performed by the installer script with signature verification). Document an opt-in auto-update flag `auto_update=false`.
- Refuse `http://` server URLs unless `allow_insecure_dev=true` (loud warning).

### Step 4 — Pilot kit (5–10 computers)
Deliver `docs/PILOT_PLAN.md` + `tools/pilot_checklist.md` with scenarios: two similar desktops (verify distinct mapping), a GPU upgrade, a dual-boot machine, an unstable-connectivity machine, an OS reinstall; metrics to monitor (incorrect links, duplicate devices, event delivery rate, outbox depth, admin time per action); go/no-go criteria for wider rollout (e.g., 0 wrong links, ≥ 99% event delivery after reconnect, all recoveries completed via documented flow).

### Exit criteria
`docker compose up` runs backend + postgres; install/uninstall scripts present and syntax-checked (`shellcheck` / `Invoke-ScriptAnalyzer` if available, otherwise noted); migrations tested from empty and from a copy; backup/restore check documented; pilot plan complete.

---

## 9. Final Verification (agent must run before declaring done)

```bash
pytest -q -m "not postgres"                         # everything on SQLite
TEST_DATABASE_URL=postgresql://... pytest -q -m postgres
ruff check . && ruff format --check .
pip-audit && bandit -r venuedesk-backend/app venuedesk-agent/agent
python tools/dump_routes.py    # every /api route shows an explicit policy
```
Then produce `docs/HARDENING_REPORT.md` containing: baseline vs final test counts, list of bugs found/fixed (with the failing-test names that prove them), constraint/migration list, endpoint-policy table, residual risks, and the pilot readiness verdict.

## 10. Definition of Done

- [ ] Baseline report exists and was reproduced on a clean checkout.
- [ ] DB-level partial unique indexes prevent duplicate ACTIVE links; concurrency tests pass on SQLite and PostgreSQL.
- [ ] Every API endpoint has an explicit, tested authorization policy; unknown routes fail closed.
- [ ] Nonce check-and-insert is atomic; pairing-token consumption is atomic and single-use; raw tokens never logged/stored.
- [ ] Fingerprints are versioned, golden-vector tested; missing evidence never counts as a match; no code links an asset by score or fingerprint alone.
- [ ] Hardware change history is append-only; ambiguous changes produce review states.
- [ ] OS installations identified by `os_installation_id`; dual boot, reinstall and recovery work end-to-end with admin approval and audit.
- [ ] Outbox is durable, idempotent end-to-end, bounded, crash-safe; failure-condition tests pass.
- [ ] CI runs unit, integration, e2e, postgres, lint, security checks on Linux (and agent on Windows), and fails on any failure; coverage targets met.
- [ ] Admin UI covers enroll, inspect, verify, suspend, reassign, recover, audit with RBAC + CSRF + confirmations.
- [ ] Production config, migrations, Docker, installers, update policy, RUNBOOK, PILOT_PLAN, THREAT_MODEL, HARDENING_REPORT complete.
- [ ] `DECISIONS.md` documents every default taken and every existing test changed.

## 11. Known Limitations to Document

- Default private-key storage is software/OS-protected; TPM-backed keys are an interface, not enabled by default.
- Some DMI serials/UUIDs need elevated privileges on Linux and may be placeholders on some OEM/virtual hardware; the system degrades to weaker evidence and routes to review.
- Separate-credential dual boot requires an admin step per additional OS.
- Motherboard/TPM replacement is an intentional manual, audited workflow.
- Effort estimates in the source plan (~27 working days sequentially) are planning assumptions, not measurements; real Windows/Linux hardware testing during the pilot is required and cannot be fully simulated.

**Begin with Phase 0 now.** After each phase append to `docs/DECISIONS.md`, commit, and continue automatically to the next phase.
