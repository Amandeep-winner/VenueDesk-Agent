# Architectural & Engineering Decisions Log

This document tracks all architectural, design, and implementation decisions made during the development of VenueDesk Agent.

| Date | Decision | Reason |
|---|---|---|
| 2026-10-11 | Standalone Monorepo Architecture (Option A) | Sibling Campus-Booking-Management-System detected. Selected standalone monorepo in VenueDesk-Agent to preserve operational isolation, provide clean CI/CD pipelines, prevent schema regressions, and simplify packaging. |
| 2026-10-11 | Workspace Root Monorepo Layout | Placed venuedesk-backend, venuedesk-agent, docs, and tools directly at root rather than nesting inside another venuedesk folder to keep paths predictable and clean. |
| 2026-10-11 | Ed25519 Cryptographic Signatures | Followed spec §1 to use Ed25519 via Python cryptography library for asymmetric request signing and device authentication. |
| 2026-10-11 | FileKeyStore with ACL/DPAPI protection | Default key store implements local filesystem storage with restricted permissions (0600 on POSIX, ACL/DPAPI on Windows), with a stub for TpmKeyStore. |
| 2026-10-11 | Phase 3 Canonicalization and Degrading Collectors | Implemented FINGERPRINT_VERSION=1 SHA-256 fingerprinting, HMAC field hashes, SQLite local state, and hardware collectors with graceful fallback to None. |
| 2026-10-11 | Phase 4 Enrollment and Pairing Token Architecture | Built transactional enrollment with proof of possession, atomic pairing token consumption, rate limiting, and fake endpoint test suite. |
| 2026-10-11 | Phase 5 Authenticated Communication and Rotation | Implemented signed HTTP request client, exponential backoff with jitter and Retry-After support, duplicate device detection, offline marking, and asymmetric credential rotation. |
| 2026-10-11 | Phase 6 Inventory, Telemetry, and Offline Outbox | Implemented full system/hardware/process/service inventory collectors, SQLite priority outbox queue with pressure shedding (never dropping priority-0 items), batch telemetry ingestion with 500-sample limit, retention pruning, and admin query API. |
| 2026-10-11 | Phase 7 Identity Reconciliation and Events | Implemented §4.6 diffing, severity policy, advisory similarity scoring (never auto-linking assets), decision engine determine_device_identity(obs), admin approval and pairing endpoints, and all 12 specification acceptance tests with >= 90% coverage on identity_service. |
| 2026-10-11 | Phase 8 Recovery and Verification Workflows | Implemented OS reinstall recovery, physical verification, and motherboard replacement workflows per spec §4.8 and §25. |
| 2026-10-11 | Phase 9 Remote Jobs and Secure Execution | Implemented allowlisted remote job service, dispatch/poll/result API, agent executor, and strict shell=False security invariants per spec §4.10. |
| 2026-10-11 | Phase 10 Server-Rendered Admin Infrastructure UI | Built Bootstrap 5 UI under /admin/infrastructure/ with CSRF protection, RBAC checks, spec §42/§43/§44 blocks, Chart.js sparkline, pairing token generation, and approval queues. |
| 2026-10-11 | Phase 11 Packaging, Deployment, and Hardening | Created Linux systemd sandboxed service, evidence cache helper, Windows service installer, production Dockerfile, RUNBOOK.md, and THREAT_MODEL.md. |
| 2026-10-11 | Phase 12 Full End-to-End Validation | Implemented 11-stage in-process E2E lifecycle test suite, fake endpoint simulation tool, and validation report. |

## Phase 8 Details

Implemented endpoint recovery workflow following OS reinstall or state loss.
The agent generates a new key pair and submits a signed recovery request with hardware evidence.
The decision engine matches existing candidate devices based on strong hardware anchors.
Administrators review and approve recovery requests via the admin API.
Approving recovery rotates credentials, increments the credential version, and marks previous OS installations as historical.
Implemented physical verification workflow linking verification audit records, marking hardware snapshots trusted, and activating assets in service.
Implemented motherboard replacement workflow that closes the old device link with reason and generates a new pairing token for the same institutional asset.
This ensures the asset retains complete operational history across endpoint replacements.

## Phase 9 Details

Implemented remote jobs subsystem strictly restricted to allowlisted operations per specification section 4.10.
The backend exposes job dispatch and history endpoints under `/api/v1/admin/devices/{id}/jobs` guarded by RBAC checks.
The agent polls pending jobs via device-authenticated endpoints `/api/v1/agents/jobs` and `/api/v1/agents/jobs/poll`.
Execution results are recorded back to `/api/v1/agents/jobs/{id}/result`.
Allowlisted handlers enforce strict boundary checks.
Diagnostic targets must be members of the local diagnostic allowlist.
Service restarts are rejected if the requested service is not explicitly in the agent configuration approved services list.
Network diagnostics enforce target host allowlisting and port range constraints.
Agent log collection enforces a 1 MB cap and redacts pairing tokens and sensitive secret patterns.
Under no circumstances is `shell=True` permitted anywhere in the agent codebase.
An automated test continuously scans the agent source tree to prevent shell injection vectors.

## Phase 10 Details

Implemented server-rendered administrative user interface using Bootstrap 5 under `/admin/infrastructure/`.
The interface enforces constant-time session CSRF token validation on all state-mutating requests.
Role-based access control enforces `infra_admin` privileges for mutative actions and `infra_viewer` for read-only inspection.
The devices list provides multi-axis filtering across status, online state, IP addresses, and operating systems.
The device detail page implements specification section 42 with asset mapping, physical device identity, observed hardware inventory, and a live Chart.js utilization sparkline.
Operating system installations are presented matching specification section 43 with distinct active and historical states.
Asset link history is displayed matching specification section 44 to preserve institutional continuity.
The unclaimed devices discovery view enables manual asset pairing workflows.
The asset pairing view generates single-use pairing tokens shown exactly once with copy actions, CLI enrollment snippets, and SVG QR codes.
The identity changes and recovery queue surfaces deviations and enables one-click approval workflows.
The physical verification form captures auditor observations per specification section 57.
The audit log viewer displays immutable compliance trails with old and new state diffs.

## Phase 11 Details

Created production packaging and deployment installers for Linux and Windows endpoints.
The Linux systemd service unit runs under a dedicated `venuedesk` unprivileged user with strict sandbox restrictions.
A root-owned pre-start helper refreshes hardware DMI identifiers to a restricted cache file before unprivileged agent startup.
The Windows installer configures `C:\ProgramData\VenueDesk` with restrictive NTFS ACL permissions and registers the service wrapper.
Created production Dockerfile and environment templates enforcing HTTPS and secure cookies.
The agent enforces HTTPS server endpoints and rejects unencrypted connections unless explicitly overridden for local development.
Logging setup applies structured filtering that redacts pairing tokens and secrets from messages and argument dictionaries.
Documented operational procedures in `RUNBOOK.md` and detailed security controls in `THREAT_MODEL.md`.

## Phase 12 Details

Implemented a comprehensive end-to-end lifecycle test suite verifying all 11 stages of the device operational lifecycle.
The suite drives an in-process Flask server with authentic Ed25519 cryptographic signing, replay checks, and transactional database integrity.
Stages cover asset provisioning, single-use token generation, agent enrollment, physical verification sign-off, heartbeats and telemetry, benign hardware drift, OS reinstall recovery, dual-boot secondary OS discovery, motherboard replacement, clone detection, and revocation.
Enhanced the fake endpoint simulation tool `tools/fake_endpoint.py` with multi-stage lifecycle simulation and telemetry streaming.
Published `docs/E2E_REPORT.md` summarizing architecture, validated stages, and operational metrics.

## Identity Hardening & Production Readiness Decisions

| Date | Phase | Decision | Reason |
| --- | --- | --- | --- |
| 2026-10-14 | Phase 0 | Established baseline with 133 passing tests across backend, agent, and e2e suites. | Operating rule 3 requires verifying baseline reproducibility before introducing identity refactoring. |
| 2026-10-14 | Phase 1 | Rewrote device pairing into canonical `pair_device` service function, added partial unique indexes `uq_active_link_per_asset` and `uq_active_link_per_device`, and created duplicate link cleanup runbook. Initial tests reproduced that the legacy code lacked row locks, lacked active device link checks, permitted concurrent duplicate links under race conditions, and constructed links outside a unified module. | Phase 1 requirements mandate single active link database constraints, atomic reassignment, and centralized link creation to prevent asset-device corruption. |
| 2026-10-14 | Phase 2 | Hardened authentication pipeline with 7-step cryptographic verification order, atomic single-statement nonce insertion and token consumption, centralized `@enforce_policy` decorator with complete endpoint policy registry, `RedactingFilter` for logs, and fail-closed security for all `/api/` routes. | Eliminates check-then-insert race conditions in replay defense, prevents information leakage by returning uniform 401 and 400 responses, and guarantees endpoint access invariants across all device lifecycle states. |
| 2026-10-14 | Phase 3 | Pinned fingerprint v1 algorithm and golden vector, enforced tri-state field comparison (None == None is UNKNOWN), established HardwareChangeRecord append-only audit trail, and implemented granular hardware change classification. | Eliminates false matches on empty or degraded evidence fields, preserves forensic hardware history across updates, and prevents automatic re-pairing without administrative authorization. |

## Phase 3 Hardening Details

Pinned fingerprint version 1 algorithm with golden test vectors to guarantee cross-version hash consistency.
Missing evidence fields (`None == None`) strictly evaluate to tri-state `UNKNOWN` rather than `MATCH`.
`UNKNOWN` fields contribute 0 to the similarity score numerator and are excluded from the denominator.
Established `hardware_change_records` append-only audit table tracking every field deviation and authorization requirement.
Granular classification categorizes changes into low severity (RAM, GPU, hostname, IP), medium severity (disk), and high severity (motherboard, TPM, multi-anchor conflicts).
Credential rotation preserves physical device records and active asset links while incrementing credential versions.
