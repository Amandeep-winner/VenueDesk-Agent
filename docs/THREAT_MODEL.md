# VenueDesk Threat Model & Security Controls

This document details the threat model for the VenueDesk endpoint agent and control plane based on specification section 69.
It describes identified threat vectors, attacker motivations, and corresponding technical safeguards.

## 1. System Security Boundary and Assets

The VenueDesk architecture divides security domains into two distinct areas:
1. **Endpoint Tier:** Potentially hostile or un-trusted physical workstations located in public labs, subject to physical tampering, network sniffing, and OS re-installations.
2. **Control Plane Tier:** Centralized Flask server and PostgreSQL database storing institutional asset registries, telemetry history, and verification audit trails.

The critical assets protected under this threat model include:
- Endpoint private keys (Ed25519) stored strictly on the local machine.
- Institutional asset identity and physical mapping ground-truth.
- Remote job execution boundary to prevent arbitrary command injection.
- Single-use enrollment tokens.
- Cryptographic nonces and timestamp freshness to prevent request replay.

## 2. Threat Analysis & Countermeasure Matrix (Spec §69)

| Threat ID | Threat Scenario | Attack Vector & Impact | Technical Control / Mitigation |
|---|---|---|---|
| **T-01** | Golden Image Cloning / Identity Duplication | An admin captures an image containing agent state and deploys it to 50 workstations, causing conflicting heartbeats and identity hijacking. | Golden image rule: state and keys are never baked into images. If two agents transmit heartbeats with identical credentials but differing instance IDs or fingerprints within `DUPLICATE_WINDOW_SECONDS`, the server emits `DUPLICATE_DEVICE_IDENTITY` (CRITICAL) and suspends the device. |
| **T-02** | Replay of Authenticated Agent Requests | An eavesdropper records signed heartbeat or telemetry traffic and replays it to simulate online status or fabricate metrics. | Every request contains a timestamp, a unique 32-character hex nonce (`X-Nonce`), and an Ed25519 signature over the canonical request string. The server enforces a clock skew window (default 120s) and rejects replayed nonces. |
| **T-03** | Pairing Token Interception and Sniffing | A passive network observer captures an enrollment token in transit or retrieves it from logs. | Tokens follow the `PAIR-...` format with 32 urlsafe bytes of entropy. Tokens are single-use, scoped strictly to one asset, expire in 24 hours, and are stored hashed with SHA-256. Raw tokens are displayed once in the admin UI and never logged. HTTPS is strictly enforced. |
| **T-04** | Arbitrary Shell Execution via Remote Jobs | An attacker compromises an admin account or spoofs job payloads to execute arbitrary bash commands or malware on endpoints. | Remote jobs are strictly restricted to a hardcoded allowlist: `REFRESH_INVENTORY`, `COLLECT_DIAGNOSTICS`, `COLLECT_LOGS`, `RESTART_APPROVED_SERVICE`, `REFRESH_CONFIGURATION`, `RUN_NETWORK_DIAGNOSTIC`. Under no circumstances is `shell=True` allowed in the codebase. Service restarts and diagnostic targets are validated against immutable local agent configuration allowlists. |
| **T-05** | Unauthorized Endpoint Spoofing | An attacker modifies local MAC, IP, or hostname to mimic another computer in the venue. | IP, MAC, hostname, and OS machine-id are explicitly rejected as identity authority. Hardware fingerprinting uses a versioned canonical representation combined with HMAC hashing using a deployment salt. Primary continuity is guaranteed cryptographically by asymmetric Ed25519 signatures. |
| **T-06** | Compromised Private Key / Rogue Endpoint | An adversary extracts the endpoint private key from memory or disk and attempts rogue communication. | Key files are protected with strict permissions (0600 on Linux, DPAPI / SYSTEM-only ACL on Windows). An administrator can revoke the device via the admin UI (`POST /revoke`), immediately cutting off access. In addition, authenticated credential rotation allows generating a fresh key pair and retiring the old credential version. |
| **T-07** | Stolen Chassis / Hardware Swapping | A user steals a workstation and replaces the motherboard with incompatible or rogue hardware. | Major changes to strong hardware anchors (UUID, motherboard serial, BIOS serial, TPM) trigger `IDENTITY_CHANGE_DETECTED` (HIGH severity). The device transitions into `PENDING_REVERIFICATION` status, blocking normal operation until physically inspected and approved by an administrator. |
| **T-08** | Man-in-the-Middle (MitM) Inspection | An attacker on the local venue network terminates HTTP connections or injects forged payloads. | The agent strictly rejects unencrypted `http://` server URLs unless `allow_insecure_dev = true` is explicitly configured. Production server deployments enforce `Strict-Transport-Security` (HSTS) and secure session cookies. |
| **T-09** | Log Exposure of Tokens and Credentials | Log files collected or forwarded to centralized observability inadvertently expose pairing tokens or private keys. | The agent includes an automated `RedactingFilter` that sanitizes log records before emission. Regex patterns automatically replace pairing tokens (`PAIR-...`), bearer tokens, passwords, and private keys with `[REDACTED]`. Log collection jobs enforce a 1 MB cap and sanitize all output. |
| **T-10** | Unclaimed Device Hijacking | Unclaimed enrollment is exploited to flood the database with bogus devices. | `ALLOW_UNCLAIMED_ENROLLMENT` defaults to `false`. Unclaimed devices are never linked to assets automatically; only an authenticated administrator can explicitly pair an unclaimed device to an asset. |

## 3. Cryptographic Implementation Details

### 3.1 Asymmetric Authentication (Ed25519)

Every device-authenticated request computes a canonical string consisting of:
```
METHOD
PATH_WITH_QUERY
TIMESTAMP
NONCE
SHA256_HEX(RAW_BODY)
```

The endpoint signs this exact sequence using its local Ed25519 private key.
The server verifies the signature against the stored public key associated with `X-Device-ID`.
Constant-time digest comparisons are utilized to resist timing side-channel attacks.

### 3.2 Evidence Canonicalization and Salting

Hardware evidence strings are normalized (trimmed, converted to lower case, collapsed whitespace, placeholder values converted to null).
Lists of disks, GPUs, and network interfaces are deduplicated and sorted.
Sensitive individual hardware identifiers are hashed locally via `HMAC-SHA256(key=DEPLOYMENT_SALT, msg=value)` before transmission.
Raw serial numbers and identifiers are never transmitted in plaintext or stored unhashed in central databases.

## 4. Operational Security Recommendations

1. Always run production agents over HTTPS with a valid institutional TLS certificate.
2. Restrict physical access to server rooms and ensure database backups are encrypted at rest.
3. Review the `AuditLog` view periodically for anomalous credential rotations or hardware approvals.
4. Keep `ALLOW_UNCLAIMED_ENROLLMENT=false` in high-security venues.
5. In the event of a lost or stolen laptop, issue an immediate revocation via the Admin Portal.
