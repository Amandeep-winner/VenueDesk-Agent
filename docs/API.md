# VenueDesk Control Plane API Specification

## 1. Authentication and Request Verification Pipeline

All agent-to-control-plane communications (except bootstrap endpoints `/enroll` and `/recover`) require asymmetric Ed25519 cryptographic authentication.
Requests must present the following mandatory HTTP headers:
- `X-Device-ID`: The canonical device identifier (e.g., `VD-DEVICE-XXXXXXXX`).
- `X-Timestamp`: Integer Unix epoch timestamp in seconds.
- `X-Nonce`: Unique per-request nonce (minimum 16 hexadecimal or alphanumeric characters).
- `X-Key-Version`: Integer credential version of the registered device public key.
- `X-Signature`: Base64-encoded raw Ed25519 digital signature.

### Verification Order (7-Step Pipeline)

Every protected endpoint executes the following verification pipeline in strict order:
1. Validate required headers and verify body size does not exceed `MAX_CONTENT_LENGTH`.
2. Validate timestamp skew against `CLOCK_SKEW_SECONDS` (default 120 seconds).
3. Query device record and verify `X-Key-Version` matches the current `credential_version`.
4. Verify Ed25519 signature over the canonical message: `METHOD\nPATH_WITH_QUERY\nTS\nNONCE\nsha256_hex(raw_body)`.
5. Atomically register the nonce in `request_nonces` under unique constraint `(device_id, nonce)`.
   If a duplicate nonce is detected, the request is rejected immediately as a replay attack.
   The nonce is registered only after signature verification succeeds to prevent unauthenticated resource exhaustion.
6. Enforce endpoint access policy based on the current `device.status`.
   If the device state is not in the allowed state set for the endpoint, access is rejected with `403 {"error":"device_blocked"}`.
7. Execute the requested controller operation.

To prevent side-channel information leaks, any failure during steps 1 through 5 returns the generic response:
`401 {"error": "unauthorized", "message": "..."}`.
Specific failure details are logged internally with sensitive tokens and keys redacted.

---

## 2. Pairing Token Lifecycle and Consumption Semantics

Pairing tokens are cryptographically generated using 32 bytes of secure entropy prefixed with `PAIR-`.
Tokens are stored hashed using SHA-256 and are never persisted in plaintext.
Each token is scoped to a specific target `Asset` and has an explicit `expires_at` timestamp.

### Atomic Consumption Guarantee

Pairing token validation and consumption occur as a single atomic SQL statement:
`UPDATE enrollment_tokens SET status='USED', used_at=:now, used_by_device_id=:device_id WHERE token_hash=:hash AND status='ACTIVE' AND expires_at > :now AND revoked_at IS NULL`.
The database execution must report exactly 1 affected row.
If zero rows are affected, the token is rejected as invalid, expired, or already used.

### Transactional Atomicity Policy

A pairing token is consumed only if the entire enrollment transaction commits.
Token consumption, device creation, and asset-device linking execute within the same database transaction.
If an enrollment fails (due to invalid proof of possession, hardware validation, or link conflicts), the entire database transaction rolls back.
Consequently, a failed enrollment attempt leaves the pairing token in its original `ACTIVE` state.
All token rejection responses return the uniform error code:
`400 {"error": "invalid_enrollment_token"}`.
This error format ensures no internal asset or device existence details are leaked to external callers.

---

## 3. Endpoint Security Policy Matrix

Every route registered under `/api/` enforces an explicit security policy.
Unregistered routes fail closed and reject all incoming requests.

| Endpoint | Path | Auth Mechanism | Allowed Device States / Roles | Rate Limit |
|---|---|---|---|---|
| `agents.enroll` | `POST /api/v1/agents/enroll` | Token or Unclaimed Flag | Public / Token Validation | 10/min |
| `agents.recover` | `POST /api/v1/agents/recover` | None + Evidence Signature | Public / Recovery Queue | 10/min |
| `agents.recover_status` | `GET /api/v1/agents/recover/status` | Device Signature or Query ID | `PENDING_REVERIFICATION` | Default |
| `agents.heartbeat` | `POST /api/v1/agents/heartbeat` | Ed25519 Device Signature | `ACTIVE`, `OFFLINE`, `PENDING_VERIFICATION`, `PENDING_REVERIFICATION` | Default |
| `agents.get_config` | `GET /api/v1/agents/config` | Ed25519 Device Signature | `ACTIVE`, `OFFLINE`, `PENDING_VERIFICATION`, `PENDING_REVERIFICATION` | Default |
| `agents.post_inventory` | `POST /api/v1/agents/inventory` | Ed25519 Device Signature | `ACTIVE`, `OFFLINE`, `PENDING_VERIFICATION`, `PENDING_REVERIFICATION` | Default |
| `agents.post_identity` | `POST /api/v1/agents/identity` | Ed25519 Device Signature | `ACTIVE`, `OFFLINE`, `PENDING_VERIFICATION`, `PENDING_REVERIFICATION` | Default |
| `agents.post_telemetry` | `POST /api/v1/agents/telemetry` | Ed25519 Device Signature | `ACTIVE`, `OFFLINE` | Default |
| `agents.poll_jobs` | `GET /api/v1/agents/jobs` | Ed25519 Device Signature | `ACTIVE` | Default |
| `agents.post_job_result` | `POST /api/v1/agents/jobs/<id>/result` | Ed25519 Device Signature | `ACTIVE` | Default |
| `agents.rotate_credential` | `POST /api/v1/agents/rotate-credential` | Ed25519 Device Signature | `ACTIVE`, `PENDING_REVERIFICATION` | Default |
| `assets.generate_pairing_token_endpoint` | `POST /api/v1/admin/assets/<id>/pairing-token` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `assets.revoke_pairing_token_endpoint` | `DELETE /api/v1/admin/assets/<id>/pairing-token` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.pair_device_endpoint` | `POST /api/v1/admin/devices/<id>/pair` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.replace_endpoint_endpoint` | `POST /api/v1/admin/devices/<id>/replace-endpoint` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.verify_device_endpoint` | `POST /api/v1/admin/devices/<id>/verify` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.approve_hardware_change_endpoint` | `POST /api/v1/admin/devices/<id>/approve-hardware-change` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.approve_recovery_endpoint` | `POST /api/v1/admin/devices/<id>/approve-recovery` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.create_device_job_endpoint` | `POST /api/v1/admin/devices/<id>/jobs` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.get_device_jobs_endpoint` | `GET /api/v1/admin/devices/<id>/jobs` | Session / HTTP Basic Auth | `infra_admin`, `infra_viewer` | Default |
| `devices.get_telemetry_endpoint` | `GET /api/v1/admin/devices/<id>/telemetry` | Session / HTTP Basic Auth | `infra_admin`, `infra_viewer` | Default |
| `devices.create_os_enrollment_token_endpoint` | `POST /api/v1/admin/devices/<id>/os-token` | Session / HTTP Basic Auth | `infra_admin` | Default |
| `devices.get_recovery_requests_endpoint` | `GET /api/v1/admin/devices/recovery-requests` | Session / HTTP Basic Auth | `infra_admin`, `infra_viewer` | Default |
| `devices.get_unclaimed_devices_endpoint` | `GET /api/v1/admin/devices/unclaimed` | Session / HTTP Basic Auth | `infra_admin`, `infra_viewer` | Default |

