# Baseline Report: VenueDesk-Agent Identity Hardening

## Overview
This document establishes the verified Phase 0 baseline for the `VenueDesk-Agent` codebase before any identity or security refactoring.
All tests were executed against an unmodified checkout in the virtual environment.

## 1. Test Suite Execution Counts

The test suite was run using `pytest -v` across all three project test areas.

- **Total Tests Collected**: 133
- **Passed**: 133
- **Failed**: 0
- **Skipped**: 0
- **Errors**: 0

### Breakdown by Suite
- `venuedesk-backend/tests/`: 71 passed, 0 failed, 0 skipped
- `venuedesk-agent/tests/`: 61 passed, 0 failed, 0 skipped
- `tests/e2e/`: 1 passed, 0 failed, 0 skipped

Raw pytest terminal output is captured in `docs/baseline/pytest_baseline.txt`.
A second run verified identical pass and fail counts (133 passed).

## 2. API Endpoints and Authorization Status

The script `tools/dump_routes.py` iterated all Flask application routes to inspect route rules, view functions, and auth decorators.
Raw table output is stored in `docs/baseline/routes_baseline.txt`.

### Key Findings
1. Agent-facing endpoints under `/api/v1/agents/` use `@require_device_auth` for signed requests.
2. Unsigned public endpoints (`/api/v1/agents/enroll`, `/api/v1/agents/recover`, `/api/v1/agents/recover/status`) rely on manual in-handler validation.
3. Admin endpoints under `/api/v1/admin/` use `@require_role` or `@require_admin`.
4. Admin UI routes under `/admin/infrastructure/` use `@require_ui_role`.
5. There is currently no centralized per-endpoint per-state policy matrix (`ENDPOINT_POLICY`) to ensure fail-closed security.

## 3. Database Schema and Models

The script `tools/dump_models.py` inspected all 16 database tables via SQLAlchemy inspector.
Raw model dump is stored in `docs/baseline/models_baseline.txt`.

### Discovered Tables
1. `asset_device_links`
2. `asset_sequences`
3. `assets`
4. `audit_logs`
5. `device_events`
6. `device_identity_evidence`
7. `device_inventory`
8. `device_jobs`
9. `device_recovery_requests`
10. `enrollment_tokens`
11. `os_installations`
12. `physical_devices`
13. `request_nonces`
14. `telemetry`
15. `users`
16. `verifications`

## 4. Architectural Concern Mapping

The core functional areas live in the following files:

- **Enrollment**:
  - Agent: `venuedesk-agent/agent/core/enrollment_client.py` and `agent/cli.py`.
  - Backend: `venuedesk-backend/app/services/enrollment_service.py` (`enroll_agent`), and route `POST /api/v1/agents/enroll` in `app/api/agents.py`.
- **Pairing**:
  - Backend service: `venuedesk-backend/app/services/identity_service.py` (`pair_unclaimed_device`).
  - Admin endpoint: `POST /api/v1/admin/devices/<device_id>/pair` in `app/api/devices.py`.
  - Admin UI: `POST /admin/infrastructure/unclaimed/<device_id>/pair` in `app/api/admin_infra.py`.
- **Identity Reconciliation**:
  - Agent: `venuedesk-agent/agent/identity/fingerprint.py`, `agent/identity/reconciliation.py`, and collectors in `agent/collectors/`.
  - Backend service: `venuedesk-backend/app/services/identity_service.py` (`determine_device_identity`, `classify_identity_change`, `reconcile_device_evidence`, `reconcile_inventory_update`).
  - Backend endpoints: `POST /api/v1/agents/identity` and `POST /api/v1/agents/inventory` in `app/api/agents.py`.
- **Authentication**:
  - Agent: `venuedesk-agent/agent/security/keys.py` and `agent/communication/client.py`.
  - Backend: `venuedesk-backend/app/security/signatures.py` (`canonical_string`, `verify`, `require_device_auth`), and `app/security/rbac.py`.
- **Nonce and Replay Protection**:
  - Agent: `venuedesk-agent/agent/communication/client.py` (`X-Nonce` header generation).
  - Backend: `venuedesk-backend/app/security/replay.py` (`check_and_record_nonce`) using `request_nonces` table.
- **Token Consumption**:
  - Backend: `venuedesk-backend/app/security/tokens.py` (`create_token_for_asset`, `verify_and_consume_token`), used in `app/services/enrollment_service.py`.
- **OS-Installation Upsert**:
  - Backend: `venuedesk-backend/app/services/identity_service.py` (`upsert_os_installation`), using model `OSInstallation` in `app/models/device.py`.
  - Agent: `venuedesk-agent/agent/collectors/os_info.py`.
- **Outbox**:
  - Agent: `venuedesk-agent/agent/storage/outbox.py` and `agent/communication/retry.py`.
  - Backend: Ingestion endpoints currently lack a dedicated server-side idempotency table (`processed_events`).
- **Remote Jobs**:
  - Backend: `app/models/device.py` (`DeviceJob`), `app/api/devices.py`, and `app/api/agents.py`.
  - Agent: `venuedesk-agent/agent/jobs/allowlist.py`, `agent/jobs/executor.py`, and `agent/jobs/poller.py`.

## 5. Existing Identity-Related Tests

The baseline test run contains 33 identity-related tests across backend and agent:

- `venuedesk-backend/tests/test_admin_ui.py::test_pairing_token_generated_and_shown_once_only`
- `venuedesk-backend/tests/test_admin_ui.py::test_unclaimed_device_pairing_workflow`
- `venuedesk-backend/tests/test_enrollment.py::test_enrollment_happy_path`
- `venuedesk-backend/tests/test_enrollment.py::test_enrollment_token_single_use`
- `venuedesk-backend/tests/test_enrollment.py::test_enrollment_expired_or_revoked_token`
- `venuedesk-backend/tests/test_enrollment.py::test_enrollment_proof_of_possession_mismatch`
- `venuedesk-backend/tests/test_enrollment.py::test_two_near_identical_endpoints_map_to_different_assets`
- `venuedesk-backend/tests/test_enrollment.py::test_unclaimed_enrollment_mode`
- `venuedesk-backend/tests/test_enrollment.py::test_enrollment_rate_limiting`
- `venuedesk-backend/tests/test_enrollment.py::test_admin_pairing_token_endpoints`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_ip_change`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_hostname_change`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_gpu_upgrade`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_ssd_replacement`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_os_reinstall`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_identical_machine`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_duplicate_credential`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_motherboard_replacement`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_dual_boot_two_os_one_device`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_ram_upgrade`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_score_never_links_asset`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_golden_image_clones_are_distinct`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_similarity_score_calculation`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_admin_unclaimed_and_pair_endpoints`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_decision_engine_branches`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_reconcile_tpm_and_nic_changed`
- `venuedesk-backend/tests/test_identity_reconciliation.py::test_identity_service_error_handling`
- `venuedesk-agent/tests/test_collectors.py::test_collect_identity_evidence_returns_evidence_object`
- `venuedesk-agent/tests/test_database.py::test_identity_store_device_lifecycle`
- `venuedesk-agent/tests/test_enrollment_client.py::test_agent_refuses_insecure_server_by_default`
- `venuedesk-agent/tests/test_enrollment_client.py::test_agent_refuses_duplicate_enrollment_without_force`
- `venuedesk-agent/tests/test_enrollment_client.py::test_agent_enrollment_success_persists_credentials`
- `venuedesk-agent/tests/test_enrollment_client.py::test_agent_force_reenrollment`
- `venuedesk-agent/tests/test_fingerprint.py::test_normalization_placeholders`
- `venuedesk-agent/tests/test_fingerprint.py::test_normalization_casing_and_whitespace`
- `venuedesk-agent/tests/test_fingerprint.py::test_virtual_nic_filtering`
- `venuedesk-agent/tests/test_fingerprint.py::test_norm_list_sorting_and_deduplication`
- `venuedesk-agent/tests/test_fingerprint.py::test_fingerprint_deterministic_and_order_independent`
- `venuedesk-agent/tests/test_fingerprint.py::test_fingerprint_excludes_volatile_fields`
- `venuedesk-agent/tests/test_fingerprint.py::test_field_hash_hmac`
- `venuedesk-agent/tests/test_fingerprint.py::test_evidence_dataclass_anchors`
- `venuedesk-agent/tests/test_reconciliation.py::test_diff_evidence_detects_hardware_changes`
- `venuedesk-agent/tests/test_reconciliation.py::test_diff_inventory_detects_inventory_changes`

## 6. Known Bugs and Missing Protections Discovered During Audit

1. **Lack of Database-Level Partial Unique Constraints on Links**:
   - In `venuedesk-backend/app/models/device.py` lines 99-120, single active link enforcement is done via a SQLAlchemy Python event hook `validate_single_active_link`.
   - Python-level event hooks do not serialize concurrent transactions under default transaction isolation.
   - Database partial unique indexes `uq_active_link_per_asset` and `uq_active_link_per_device` are missing.

2. **Concurrency Race in `pair_unclaimed_device`**:
   - In `venuedesk-backend/app/services/identity_service.py` lines 516-560, pairing reads the device and asset without pessimistic row locking (`with_for_update()`).
   - Reassignment does not close old active links atomically in the same transaction.

3. **Missing Centralized Endpoint Policy Registry**:
   - In `venuedesk-backend/app/api/agents.py`, endpoints implement piecemeal status checks.
   - There is no central matrix mapping device statuses (`UNCLAIMED`, `PENDING_VERIFICATION`, `ACTIVE`, `OFFLINE`, `PENDING_REVERIFICATION`, `SUSPENDED`, `REVOKED`, `RETIRED`) to allowed routes.
   - Unauthenticated routes do not fail closed by default.

4. **Non-Atomic Nonce Insertion**:
   - In `venuedesk-backend/app/security/replay.py`, nonce verification does a lookup first and then an insert, rather than catching duplicate insert `IntegrityError`.
   - This leaves a window for concurrent requests with identical nonces to slip through.

5. **Missing Hardware Change Audit Table**:
   - In `venuedesk-backend/app/models/device.py`, hardware changes are captured as ephemeral device events, but there is no dedicated `hardware_change_records` table to track structured before and after snapshots.

6. **Missing Server-Side Idempotency Store for Agent Events**:
   - In `venuedesk-backend/app/api/agents.py`, telemetry and inventory batches lack an event deduplication table (`processed_events`).
   - Retried outbox batches risk processing redundant side effects.

7. **Dual-Boot and OS-Installation Tracking by `agent_instance_id` instead of `os_installation_id`**:
   - In `venuedesk-backend/app/models/device.py` lines 145-175, OS installation records are keyed by `(device_id, os_family, os_machine_id_hash)` rather than an immutable UUID `os_installation_id`.
   - Distinct installations under the same OS family on the same machine conflict without multi-credential support.
