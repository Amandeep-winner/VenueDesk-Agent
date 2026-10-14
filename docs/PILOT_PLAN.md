# VenueDesk Endpoint Agent Pilot Plan

## 1. Overview and Pilot Scope

This document details the operational deployment plan for running the VenueDesk Endpoint Agent pilot across 5 to 10 physical computers in institutional lab environments.
The goal of this pilot is to validate identity reconciliation, device-to-asset mapping integrity, dual-boot support, offline tolerance, and administrative recovery under realistic operational conditions.

## 2. Target Machines and Allocation

The pilot fleet comprises 5 to 10 physical machines distributed across academic computer laboratories.

| Machine ID | Lab / Room | Hardware Profile | Target Scenario | Assigned Asset Tag |
|---|---|---|---|---|
| PC-PILOT-01 | AI Lab 101 | Intel Core i7, Dell OptiPlex 7090, Integrated GPU | Baseline Single-OS Desktop | VD-ASSET-000421 |
| PC-PILOT-02 | AI Lab 101 | Intel Core i7, Dell OptiPlex 7090, Integrated GPU (Identical Model) | Identical Hardware Separation | VD-ASSET-000422 |
| PC-PILOT-03 | CSE Lab 204 | AMD Ryzen 7, Custom Tower, NVIDIA RTX 3060 | Hardware Change (GPU Upgrade) | VD-ASSET-000423 |
| PC-PILOT-04 | CSE Lab 204 | Intel Core i5, HP ProDesk 400, Dual Boot (Windows 11 + Ubuntu 24.04) | Dual-Boot Multi-OS Tracking | VD-ASSET-000424 |
| PC-PILOT-05 | Electronics Lab 305 | Intel Core i5, Lenovo ThinkCentre M70q | Unstable Connectivity & Outage | VD-ASSET-000425 |
| PC-PILOT-06 | Electronics Lab 305 | Intel Core i7, HP EliteDesk 800 | Full OS Reinstall & Key Recovery | VD-ASSET-000426 |

## 3. Test Scenarios and Protocols

### Scenario A: Identical Hardware Separation
- **Target:** PC-PILOT-01 and PC-PILOT-02.
- **Protocol:** Both machines share identical motherboard models, BIOS releases, and CPU specifications.
- Generate independent pairing tokens for assets `VD-ASSET-000421` and `VD-ASSET-000422`.
- Enroll both machines simultaneously.
- Verify that each machine produces a unique device ID (`VD-DEVICE-*`) and establishes exactly one active link to its respective asset.
- **Success Criteria:** 0 overlapping device IDs; 0 cross-linked assets; DB-level partial unique indexes remain satisfied.

### Scenario B: Hardware Component Change (GPU Upgrade)
- **Target:** PC-PILOT-03.
- **Protocol:** Enroll machine with initial baseline GPU.
- Power off machine, swap GPU (or simulate swap via GPU collector override), and power on.
- Observe identity service ingestion behavior.
- Strong anchors (motherboard UUID, chassis serial) remain unchanged while component metrics shift.
- The control plane records an append-only `HardwareChangeRecord`, transitions device to `PENDING_REVERIFICATION` (or auto-approves according to policy), and alerts the administrator.
- Administrator reviews diff in web dashboard and approves change.
- **Success Criteria:** Device ID and asset link are preserved; full audit trail of previous vs new component state recorded.

### Scenario C: Dual-Boot Multi-OS Machine
- **Target:** PC-PILOT-04.
- **Protocol:** Enroll Windows 11 installation first using primary pairing token.
- Boot into secondary Ubuntu 24.04 installation.
- Generate a device-scoped OS token from the admin console (`POST /api/v1/admin/devices/<device_id>/os-token`).
- Enroll Ubuntu installation using the scoped token.
- Alternate boot sessions between Windows and Ubuntu.
- **Success Criteria:** Exactly one `physical_device` entity in database; two `os_installations` with distinct `os_installation_id`s; each OS signs telemetry with its own credential version; asset link remains stable.

### Scenario D: Unstable Connectivity and Outage Simulation
- **Target:** PC-PILOT-05.
- **Protocol:** Disconnect network cable or drop egress traffic at switch port for 4 hours.
- Generate continuous telemetry and periodic simulated inventory events during the outage.
- Reconnect network.
- Observe agent outbox drain order and retry backoff behavior.
- **Success Criteria:** Outbox persists events in SQLite WAL without corruption; events drain in strict priority order (identity events first, inventory second, telemetry third); 0 duplicate event processing on server; ≥ 99% of events delivered.

### Scenario E: OS Reinstall and Administrator Recovery
- **Target:** PC-PILOT-06.
- **Protocol:** Enroll baseline endpoint.
- Re-image machine disk completely, wiping local agent private keys and state DB.
- Install fresh agent and trigger recovery workflow: `venuedesk-agent recover --server https://control.venue.internal`.
- Hardware anchors match existing registered physical device.
- Control plane creates `DeviceRecoveryRequest` in `PENDING` state.
- Administrator reviews recovery request in UI verification queue and clicks "Approve Recovery".
- Agent polls, receives approval, stores new credential, and resumes normal telemetry.
- **Success Criteria:** Previous device ID and asset mapping are preserved; slot-isolated credential activated; audit log records approving administrator.

## 4. Key Metrics to Monitor

The pilot monitoring dashboard and daily query scripts track the following quantitative metrics:

1. **Incorrect Links:** Total count of mismatched asset-to-device relationships. Target: Exactly 0.
2. **Duplicate Active Links:** Verified by automated SQL constraint checks. Target: Exactly 0.
3. **Event Delivery Rate:** Percentage of queued events successfully acknowledged by backend after network disruptions. Target: ≥ 99.0%.
4. **Outbox Depth:** Maximum and average queue length during disconnected periods. Target: Buffer never exceeds configured memory/disk thresholds.
5. **Dropped Events:** Number of priority 1 or 2 events shed under simulated pressure. Target: 0 priority 0 events dropped; telemetry shedding logged with audit counts.
6. **Administrator Time Per Action:** Average duration required for an administrator to inspect and approve a hardware change or recovery request. Target: ≤ 60 seconds per action.

## 5. Go / No-Go Decision Criteria

At the conclusion of the 14-day pilot window, the engineering and infrastructure teams will evaluate rollout readiness based on these mandatory gates:

- **Gate 1 (Identity Integrity):** Exactly 0 incorrect device-to-asset links across all pilot machines.
- **Gate 2 (Data Loss):** ≥ 99.0% event delivery rate across all network reconnection tests.
- **Gate 3 (Recovery Reliability):** 100% of recovery and reinstall workflows successfully completed through the documented web UI workflow without manual database edits.
- **Gate 4 (Crash Safety):** 0 unhandled SQLite locking errors or database corruption instances on Windows or Linux endpoints.
- **Gate 5 (Security Posture):** 0 unauthenticated access attempts permitted to restricted endpoints; 100% policy enforcement across all routes.
