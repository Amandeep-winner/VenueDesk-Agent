# VenueDesk Product Requirements Document (PRD)

## 1. Document Overview and Purpose

This Product Requirements Document (PRD) establishes the comprehensive product specifications for the VenueDesk Agent and Control Plane infrastructure system.
The system provides enterprise-grade IT asset mapping, physical device tracking, cryptographic endpoint management, and telemetry ingestion across institutional desktop and lab fleets.
This document details the target personas, operational workflows, business rules, functional capabilities, and user experience requirements in an accessible and structured format.

## 2. Problem Statement and Strategic Context

Higher education campuses, enterprise testing centers, and distributed computer laboratories manage hundreds to thousands of physical workstations.
Traditional IT asset management tools frequently suffer from several critical shortcomings:

- They conflate the institutional asset (the financial and operational inventory entity) with transient network attributes such as IP addresses or DHCP hostnames.
- Routine lab maintenance, including operating system re-imaging and dual-boot installations, creates duplicate records and breaks historical maintenance tracking.
- Motherboard replacements often erase the identity of an asset, severing warranty history, purchase ledger links, and physical desk positioning.
- Cloned disk images deployed across identical hardware batches cause identity collisions, credential confusion, and corrupted inventory state.
- Existing endpoint agents rely on broad, unconstrained shell execution privileges that introduce severe security vulnerabilities across institutional networks.

VenueDesk solves these challenges through a strict separation between institutional assets, physical devices, and operating system installations.
The platform pairs high-entropy single-use tokens with asymmetric cryptographic identities (Ed25519) and deterministic hardware fingerprinting.
This architecture guarantees that institutional continuity is preserved across hardware repairs, re-imaging cycles, and network topology changes.

## 3. Product Vision and Guiding Invariants

VenueDesk operates under fundamental product invariants that must never be violated:

1. **Asset Separation Invariant:** The institutional Asset ID is strictly decoupled from physical hardware serials, operating system installation IDs, hostnames, and IP addresses.
2. **Authority Invariant:** Network attributes (IP addresses, hostnames, MAC addresses) and heuristic similarity scores never serve as the sole authority for asset assignment.
3. **Cryptographic Continuity:** Every enrolled physical endpoint proves its identity using a local Ed25519 private key that never leaves the machine.
4. **Single-Use Pairing:** Enrollment tokens are one-time credentials, scoped to a single asset, with strict time-to-live expiration.
5. **Human-in-the-Loop Governance:** Discrepancies, hardware swaps, and recovery candidates require explicit administrative confirmation; the system never auto-merges ambiguous hardware.
6. **Zero Shell Invariant:** Remote diagnostic jobs are strictly allowlisted; arbitrary shell execution is prohibited across the entire agent lifecycle.

## 4. User Personas and Stakeholder Needs

### 4.1 Infrastructure Administrator (IT Admin)
- **Role:** Central IT manager overseeing campus-wide computer hardware, fleet health, and security compliance.
- **Goals:** Maintain an authoritative inventory of physical workstations, approve hardware repairs, monitor fleet online status, and dispatch approved diagnostics.
- **Pain Points:** Tracking workstations across VLAN reconfigurations, resolving clone collisions, and maintaining historical records across OS upgrades.

### 4.2 Lab Technician / Field Auditor
- **Role:** On-site technician performing workstation deployments, hardware repairs, physical auditing, and room re-cabling.
- **Goals:** Quickly pair newly assembled computers to desk locations using single-use tokens or QR codes, perform physical audit sign-offs, and swap failed motherboards.
- **Pain Points:** Complex manual inventory data entry, lost asset tags, and opaque agent installation scripts.

### 4.3 Security and Compliance Officer
- **Role:** Institutional auditor ensuring least privilege, data protection, and forensic traceability.
- **Goals:** Ensure agent credentials cannot be extracted from disk images, verify that all actions are immutably audited, and ensure remote execution vectors cannot be exploited.
- **Pain Points:** Plaintext credentials in agent configs, unencrypted communication, and arbitrary remote code execution tools.

### 4.4 Department Asset Custodian
- **Role:** Departmental administrator tracking computer depreciation, warranty periods, and physical room assignments.
- **Goals:** View complete lifecycle history for each computer desk position regardless of how many times internal hardware components were serviced.
- **Pain Points:** Disjointed spreadsheets and broken links between financial purchase records and live hardware.

## 5. Core Entities and Conceptual Model

```
+-------------------------------------------------------------+
|                     Institutional Asset                     |
|           (e.g., VD-ASSET-000421 / Tag: AI-LAB-PC-07)       |
|    - Financial records, warranty, department, room, desk    |
+-------------------------------------------------------------+
                              |
                     1:1 Active Link (AssetDeviceLink)
                              |
                              v
+-------------------------------------------------------------+
|                       Physical Device                       |
|           (e.g., VD-DEVICE-A8123F00 / Ed25519 Key)          |
|    - Motherboard, CPU, chassis, BIOS anchors, status        |
+-------------------------------------------------------------+
                              |
                      1:N Installations
                              |
                              v
+-------------------------------------------------------------+
|                   OS Installations (1 or more)              |
|    - Windows 11 Pro (ACTIVE)                                |
|    - Ubuntu 24.04 LTS (ACTIVE / Dual-Boot)                  |
|    - Previous Windows 10 (HISTORICAL / Post-Reinstall)      |
+-------------------------------------------------------------+
```

### 5.1 Institutional Asset (`Asset`)
The Asset represents the physical inventory item owned by the institution.
It tracks the financial purchase date, warranty expiration, department ownership, building, room, and physical desk position.
An Asset exists before physical hardware is connected and persists even when internal hardware is completely overhauled.

### 5.2 Physical Device (`PhysicalDevice`)
The Physical Device represents the physical computer hardware unit.
It is identified by a unique ID and anchored by a local Ed25519 cryptographic key pair.
It tracks hardware component serial numbers, trusted hardware evidence snapshots, and operational lifecycle states.

### 5.3 Asset Device Link (`AssetDeviceLink`)
The relationship between an Asset and a Physical Device is modeled as an explicit, audited link.
The system enforces a strict invariant: an Asset can have at most one ACTIVE device link at any given time, and a Physical Device can have at most one ACTIVE asset link.
When hardware is replaced, the link is closed with a recorded reason, and a new link is established.

### 5.4 Operating System Installation (`OSInstallation`)
A physical computer can host one or more operating system installations over its lifespan.
In dual-boot lab setups, both operating systems (for example, Windows 11 and Ubuntu 24.04) are registered under the same Physical Device.
When an operating system is re-installed, the previous installation is marked as `HISTORICAL`, while the new installation is registered as `ACTIVE`.

## 6. End-to-End User Journeys and Workflows

### 6.1 Asset Provisioning and Token Generation
1. The IT Administrator navigates to the Institutional Assets view in the Administrative Portal.
2. The administrator creates a new asset record, providing an asset tag (for example, `AI-LAB-PC-07`), department, building, room, and desk position.
3. The asset is saved in the `DRAFT` or `PENDING_AGENT` status.
4. The administrator selects **Generate Pairing Token**.
5. The system generates a cryptographically random token with the `PAIR-` prefix (for example, `PAIR-K9s7x...`).
6. The modal displays the raw token exactly once, accompanied by a quick-copy button, a ready-to-run CLI installation command, and a vector SVG QR code.
7. The server stores only the SHA-256 hash of the token with a 24-hour expiration window.

### 6.2 Endpoint Installation and Initial Enrollment
1. The field technician boots the newly installed computer at the designated lab desk.
2. The technician executes the installation command on the workstation:
   - On Linux: `sudo ./install.sh --server https://control.venue.internal --token PAIR-...`
   - On Windows: `powershell.exe -File .\install.ps1 -ServerUrl https://control.venue.internal -Token PAIR-...`
3. The agent generates a persistent Ed25519 private key stored with restricted OS permissions.
4. The agent collects hardware evidence (UUID, motherboard serial, BIOS serial, CPU, GPU, storage serials, MAC addresses) and canonicalizes a SHA-256 fingerprint.
5. Sensitive serials are hashed using salted HMAC (`DEPLOYMENT_SALT`) before transmission.
6. The agent submits an enrollment payload to the control plane containing its public key, raw pairing token, proof of possession, and hardware evidence.
7. The control plane atomically consumes the pairing token, creates the `PhysicalDevice` record in `PENDING_VERIFICATION` status, links it to the asset, and registers the initial inventory snapshot.
8. The asset transitions to `PENDING_VERIFICATION`.

### 6.3 Physical Verification Workflow (§57)
1. A physical verification auditor conducts an on-site physical inspection of the workstation.
2. The auditor navigates to the Physical Verification view in the portal.
3. The auditor verifies the physical asset barcode tag affixed to the chassis and confirms room and desk placement.
4. The auditor completes the verification form, recording audit observations and confirmation checks.
5. Submitting the form commits an immutable audit record, marks the observed hardware evidence snapshot as `trusted=true`, updates the asset verification status to `VERIFIED`, and transitions the asset to `IN_SERVICE`.

### 6.4 Continuous Operational Monitoring
1. The agent executes a continuous background loop:
   - **Heartbeats:** Dispatched every 60 seconds with an Ed25519 signature, timestamp, nonce, and local agent instance ID.
   - **Telemetry:** Buffers CPU, RAM, disk, and network metrics locally and transmits batches every 60 seconds.
   - **Inventory:** Collects full system hardware, process, and service state every 6 hours.
   - **Jobs Polling:** Checks for pending remote administrative jobs.
2. The control plane validates request signatures, checks nonces to prevent replay attacks, and updates device `last_seen` timestamps.
3. If an endpoint misses heartbeats beyond the configured threshold, the control plane marks its status as `OFFLINE` and generates an informational event.
4. When the endpoint resumes communication, valid heartbeats automatically recover its state to `ACTIVE`.

### 6.5 Routine Hardware and Network Drift
1. A technician performs benign maintenance on an active workstation (for example, upgrading the GPU, adding an NVMe SSD, or changing DHCP network subnets).
2. The agent detects the changes and transmits an updated inventory and evidence payload.
3. The server reconciliation engine calculates a component diff against the last trusted snapshot.
4. Because core hardware anchors (motherboard, BIOS, machine UUID) remain unchanged, the system assigns a high similarity score and records low-severity audit events (`GPU_CHANGED`, `DISK_CHANGED`, `IP_CHANGED`).
5. The device remains `ACTIVE` without administrative disruption.
6. An administrator can review the pending hardware changes in the portal and click **Approve Hardware Change** to promote the new snapshot to trusted baseline.

### 6.6 Operating System Reinstall Recovery
1. A lab computer is wiped and re-imaged with a clean operating system, erasing the agent local database and private key.
2. The technician installs the agent without a pairing token or runs `python -m agent.main recover`.
3. The fresh agent generates a new Ed25519 key pair and submits a signed recovery request containing current hardware evidence.
4. The control plane decision engine inspects the evidence and identifies the existing registered device based on matching motherboard, BIOS, and UUID anchors.
5. The server creates an `OS_REINSTALL_DETECTED` event, places the device into `PENDING_REVERIFICATION`, and adds the item to the Admin Recovery Queue.
6. The administrator reviews the recovery request, verifies hardware continuity, and clicks **Approve Recovery**.
7. The control plane rotates the device public key to the new key, increments the credential version to 2, marks the previous OS installation as `HISTORICAL`, creates the new `ACTIVE` OS installation, and restores full service.

### 6.7 Dual-Boot Secondary OS Discovery (§43)
1. A workstation is configured to dual-boot between Linux and Windows for specialized coursework.
2. The agent is installed on both operating system partitions.
3. The secondary operating system submits its hardware evidence and authenticates under the device credentials.
4. The control plane recognizes the identical physical hardware anchors and registers the second OS installation under the existing `PhysicalDevice`.
5. The Device Detail page displays both operating system installations in the OS summary block, allowing administrators to inspect active partitions, kernel versions, and boot history.

### 6.8 Motherboard Replacement Workflow (§25)
1. A workstation suffers a motherboard failure, requiring a technician to install a replacement motherboard and CPU.
2. Because the primary hardware anchors (motherboard serial, BIOS serial, and UUID) have changed, cryptographic and hardware continuity cannot be automatically assumed.
3. In the Admin Portal, the technician locates the device and clicks **Replace Motherboard**.
4. The control plane terminates the existing `AssetDeviceLink` with the closure reason `MOTHERBOARD_REPLACED` and transitions the old device record to `RETIRED`.
5. The system automatically creates a fresh single-use pairing token for the existing `Asset` record.
6. The technician enrolls the workstation using the new token.
7. The replacement hardware becomes the new active device for the asset, preserving all previous asset accounting, depreciation, desk positioning, and audit history.

### 6.9 Rogue Duplicate and Clone Detection (§39)
1. A technician mistakenly deploys a full raw disk clone (including private key and state files) to a second machine in the lab.
2. Both machines begin transmitting heartbeats using the same device ID and cryptographic key.
3. Because each agent instance initializes with a unique local runtime UUID, the control plane detects conflicting `agent_instance_id` values arriving within the rapid heartbeat window.
4. The control plane immediately triggers duplicate device defense:
   - Emits a `CRITICAL` severity `DUPLICATE_DEVICE_IDENTITY` audit event.
   - Transitions the device status to `SUSPENDED`.
   - Rejects conflicting requests with HTTP 403 `device_suspended`.
5. An administrator inspects the security alert in the portal, identifies the duplicate endpoint, re-images or re-enrolls the clone with its own unique identity, and restores the original device.

### 6.10 Cryptographic Revocation and Retirement
1. When a device is decommissioned, lost, or compromised, an administrator clicks **Revoke Device**.
2. The control plane transitions the device status to `REVOKED`.
3. The cryptographic signature filter immediately rejects all subsequent requests from that endpoint with HTTP 403 `device_blocked`.
4. The asset link is severed and recorded in the immutable audit log.

## 7. Functional Requirements

### 7.1 Endpoint Agent
- **Cross-Platform Execution:** Native execution on modern Linux distributions (via systemd) and Windows 10/11 / Windows Server (via Windows Service).
- **Graceful Collector Degradation:** Hardware collectors must handle missing permissions, non-standard virtualization, or omitted vendor serials gracefully by returning `None` rather than crashing.
- **Local Outbox Buffering:** When the endpoint is offline or disconnected, telemetry and inventory events must be queued in local SQLite storage with priority enforcement.
- **Restricted Remote Execution:** Remote job execution is restricted exclusively to allowlisted handlers; arbitrary shell invocations are prohibited.
- **Log Sanitation:** Plaintext pairing tokens, API secrets, private keys, and authorization headers must be stripped from local agent logs.

### 7.2 Control Plane Backend
- **Device Authentication:** Verify every authenticated request using Ed25519 digital signatures, request nonces, and clock-skew bounds.
- **Identity Decision Engine:** Deterministic evaluation of incoming hardware evidence against historical baselines returning explicit decision states (`SAME_DEVICE`, `UNKNOWN_DEVICE`, `PENDING_REVERIFICATION`, `AMBIGUOUS`, `MANUAL_VERIFICATION`).
- **Transactional State Transitions:** Atomic database operations for token consumption, device pairing, credential rotation, and link closures.
- **Telemetry Processing:** Ingest and aggregate time-series telemetry samples, enforce batch size limits (500 samples), and prune expired records.
- **Immutable Audit Logging:** Append-only compliance log capturing all administrative and system state mutations with complete actor tracking.

### 7.3 Administrative Web Portal
- **Fleet Overview:** Searchable, filterable list of managed endpoints with real-time status badges, department filters, and IP search.
- **Device Detail View:** Complete visibility into institutional asset links, physical hardware specifications, live telemetry sparklines, multi-OS installations, events timeline, and audit logs.
- **Token Generation Modal:** Single-view token presentation with clipboard copy, CLI syntax helpers, and SVG QR code rendering.
- **Queue Management:** Dedicated administrative queues for unassigned discovery devices, hardware drift approvals, and OS reinstall recoveries.
- **CSRF and RBAC Enforcement:** Session-bound anti-CSRF protection across all mutating forms and granular role-based access control.

## 8. Non-Functional Requirements

### 8.1 Reliability and Availability
- The agent daemon must withstand network interruptions, server restarts, and DNS outages with exponential backoff and randomized jitter.
- Local SQLite outbox storage must persist buffered messages across unexpected system reboots.
- The control plane backend must support stateless horizontal scaling behind a reverse proxy when using PostgreSQL.

### 8.2 Performance and Scalability
- **Heartbeat Latency:** The control plane must process signed heartbeat requests in under 20 milliseconds under normal load.
- **Agent Footprint:** The endpoint agent must consume less than 50 MB of resident memory and less than 1% CPU utilization during routine polling.
- **Outbox Capacity:** The agent local outbox must buffer up to 10,000 telemetry events during extended offline periods without degrading local system performance.

### 8.3 Security and Governance
- **Transport Security:** The agent must require HTTPS communication for all non-development environments.
- **Key Protection:** Private keys must never be transmitted over the network or written to unencrypted shared storage.
- **Zero Shell Policy:** Shell injection vulnerabilities are strictly prevented by avoiding shell invocation mechanisms.
- **Data Protection:** Hardware serial numbers are hashed using salted HMAC algorithms before leaving the physical workstation.

## 9. Success Metrics and Acceptance Criteria

| Metric | Target Objective |
|---|---|
| Identity Reconciliation Accuracy | 100% correct classification across all 11 lifecycle stages |
| Duplicate Clone Detection Time | Conflicting endpoints suspended within 120 seconds of collision |
| Automated Test Pass Rate | 100% passing across unit, integration, and E2E suites |
| Lint & Security Violations | 0 ruff errors; 0 `shell=True` occurrences in agent source code |
| Service Continuity | Asset identity preserved across 100% of motherboard replacements |
