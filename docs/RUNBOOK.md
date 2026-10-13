# VenueDesk Operations Runbook

This runbook documents operational procedures for administrators and technicians managing VenueDesk endpoints and the control plane.
Follow these standardized procedures to maintain system integrity, continuity, and compliance.

## 1. Installation and Deployment

### 1.1 Linux Endpoints (systemd)

Execute the production installer with administrative privileges.
The installer sets up a dedicated unprivileged `venuedesk` system user and sandbox filesystem restrictions.

```bash
sudo ./installers/linux/install.sh --server https://control.venue.internal --token PAIR-<TOKEN>
```

Verify service execution status and systemd journal logs.

```bash
systemctl status venuedesk-agent.service
journalctl -u venuedesk-agent.service -f
```

The systemd unit enforces strict sandboxing with `ProtectSystem=strict` and `NoNewPrivileges=true`.
Privileged hardware tables (such as DMI product UUIDs) are refreshed before unprivileged startup by `venuedesk-evidence-helper`.

### 1.2 Windows Endpoints

Open an elevated PowerShell prompt on the target workstation.
Run the PowerShell installer script targeting `C:\ProgramData\VenueDesk`.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\installers\windows\install.ps1 -ServerUrl https://control.venue.internal -Token PAIR-<TOKEN>
```

The installer configures NTFS access control lists permitting only `SYSTEM` and `BUILTIN\Administrators`.
All local state, database keys, and configuration reside in `C:\ProgramData\VenueDesk`.

### 1.3 Control Plane Backend (Docker Compose)

Deploy the Flask control plane and PostgreSQL database using Docker Compose.

```bash
cp venuedesk-backend/.env.example .env
docker compose up -d
```

Verify backend health by querying the liveness endpoint.

```bash
curl -f http://127.0.0.1:5001/healthz
```

## 2. Endpoint Enrollment Lifecycle

### 2.1 Standard Token Pairing (Recommended)

1. Open the Infrastructure Admin Portal at `/admin/infrastructure/assets`.
2. Locate the institutional asset to pair and click **Generate Token**.
3. Copy the raw single-use pairing token (`PAIR-...`).
4. Note that the raw token is displayed exactly once and cannot be retrieved again from the database.
5. On the endpoint, execute:
   `venuedesk-agent enroll --server <SERVER_URL> --token <RAW_TOKEN>`.
6. The endpoint generates an Ed25519 asymmetric key pair locally and performs an atomic proof of possession handshake.
7. The device transitions into `PENDING_VERIFICATION` status linked to the institutional asset.

### 2.2 Unclaimed Discovery Mode

If `ALLOW_UNCLAIMED_ENROLLMENT=true` is enabled in backend configuration, endpoints can enroll without a token.
1. The endpoint enrolls without a token and receives `UNCLAIMED` status.
2. The endpoint is visible under `/admin/infrastructure/unclaimed`.
3. An administrator selects an institutional asset from the dropdown and clicks **Pair Asset**.
4. The endpoint moves to `PENDING_VERIFICATION` status with an active asset link.

## 3. Physical Verification (Spec §57)

Physical verification establishes ground-truth continuity between the software endpoint and physical chassis.
1. Navigate to `/admin/infrastructure/devices/<DEVICE_ID>/verify`.
2. Select the verification method: `ADMIN_CONFIRMATION`, `QR_SCAN`, `SERIAL_CHECK`, or `ENROLLMENT_TOKEN`.
3. Record observed institutional asset tag, physical chassis serial number, and room/bench location.
4. Submit the verification form.
5. The device status updates to `ACTIVE`, the latest identity evidence snapshot is marked `trusted=true`, and the asset moves to `IN_SERVICE`.

## 4. Workstation Relocation Between Rooms or Labs

When moving an endpoint between computer labs or desks:
1. Physical location is an observed institutional attribute, not an identity anchor.
2. The agent reports the new local IP address automatically.
3. The server logs an `IP_CHANGED` event with `LOW` severity.
4. The asset link and cryptographic keys remain fully valid.
5. Update the asset location label in the asset registry if necessary.

## 5. Hardware Maintenance and Component Upgrades

### 5.1 Replacing RAM, GPU, or Secondary Storage

1. Replace the component while the machine is powered off.
2. When the machine boots, the agent detects the modified component during inventory collection.
3. A `RAM_CHANGED`, `GPU_CHANGED`, or `DISK_CHANGED` event is logged with `LOW` or `MEDIUM` severity.
4. Cryptographic continuity is preserved through unchanged private keys and motherboard anchors.
5. The endpoint remains `ACTIVE`.

### 5.2 Motherboard or TPM Replacement

A motherboard replacement changes primary hardware anchors (UUID, board serial, TPM).
1. Replacing the motherboard causes the agent identity reconciliation engine to emit `IDENTITY_CHANGE_DETECTED` (HIGH severity).
2. The device transitions into `PENDING_REVERIFICATION` to protect against unauthorized device swaps.
3. If this was an approved hardware repair, visit `/admin/infrastructure/identity-queue`.
4. Click **Approve Hardware Change** to accept the new hardware snapshot as the trusted baseline and restore `ACTIVE` status.
5. If the entire chassis or machine was replaced, use the **Replace Endpoint** action:
   The existing device link is closed with history preserved, and a fresh pairing token is generated for the institutional asset.

## 6. OS Reinstall Recovery (Spec §4.8 & §62)

When an operating system is re-imaged or reinstalled on existing hardware:
1. The fresh agent generates a new private key and detects an un-enrolled state.
2. The agent executes `venuedesk-agent recover --server <SERVER_URL>`.
3. The control plane decision engine analyzes submitted hardware evidence anchors.
4. When hardware anchors match an existing registered endpoint, a `DeviceRecoveryRequest` is created.
5. The request surfaces in the admin queue at `/admin/infrastructure/identity-queue`.
6. Click **Approve Recovery**.
7. The server updates the registered public key, increments `credential_version`, marks the prior OS installation as `HISTORICAL`, and registers the new OS installation as `ACTIVE`.

## 7. Dual-Boot Systems (Spec §43)

VenueDesk models dual-boot systems as one physical device with multiple operating system installations.
1. When booting into the second operating system (e.g. Linux partition after Windows), enroll the second agent using a pairing token scoped to the same institutional asset.
2. The server recognizes the identical hardware anchors and active asset link.
3. The control plane appends a second `OSInstallation` row linked to the same `PhysicalDevice`.
4. The OS count is derived dynamically from active OS installation rows.
5. Heartbeats from either operating system update the shared physical device record.

## 8. Asymmetric Credential Rotation

Rotate cryptographic credentials periodically or if key compromise is suspected.
1. Execute the rotation command on the endpoint:
   `venuedesk-agent rotate-credential`.
2. The agent generates a new Ed25519 key pair.
3. The agent signs a rotation payload containing the new public key using the existing authorized private key.
4. The server validates the signature, stores the new public key, and advances `credential_version`.
5. The old key is immediately revoked and all future requests require the new key.

## 9. Endpoint Revocation and Decommissioning

If a computer is retired, stolen, or decommissioned:
1. Navigate to the device detail view in the admin portal.
2. Click **Revoke Device**.
3. The device status updates to `REVOKED`.
4. All subsequent authenticated requests from the endpoint receive HTTP `403 Forbidden` (`{"error": "device_blocked"}`).
5. Associated active asset links are closed with reason recorded in audit logs.

## 10. Golden Image Deployment Procedure (Spec §27)

When creating standardized OS images (Clonezilla, Macrium, WIM, cloud golden images):
1. **Never bake agent state into the image.**
2. Install the VenueDesk agent software binaries only.
3. Ensure `/var/lib/venuedesk-agent/agent_state.db` (Linux) or `C:\ProgramData\VenueDesk\agent_state.db` (Windows) does not exist in the golden master.
4. Ensure no private key file exists in the master image.
5. On first boot of a deployed machine, the agent generates a fresh, unique `agent_instance_id` and unique Ed25519 key pair.
6. The test suite verifies that cloned images with identical hardware generate distinct cryptographic identities.

## 11. Database Backup and Disaster Recovery

### 11.1 PostgreSQL Backup

Create automated daily logical backups of the control plane database.

```bash
docker exec venuedesk-postgres pg_dump -U venuedesk -d venuedesk -F c -f /tmp/venuedesk_backup.dump
docker cp venuedesk-postgres:/tmp/venuedesk_backup.dump ./backups/venuedesk_$(date +%Y%m%d).dump
```

### 11.2 PostgreSQL Restore

Restore the database from an archive snapshot during disaster recovery.

```bash
docker cp ./backups/venuedesk_backup.dump venuedesk-postgres:/tmp/restore.dump
docker exec venuedesk-postgres pg_restore -U venuedesk -d venuedesk --clean /tmp/restore.dump
```

## 12. Telemetry and Audit Retention Pruning

To maintain optimal database performance, purge telemetry samples older than the retention window.
Run the database cleanup command via Flask CLI:

```bash
flask purge-telemetry --older-than-days 30
```

Request nonces are opportunistically pruned on writes and can be cleaned via CLI:

```bash
flask purge-nonces
```

## 13. Duplicate Active Link Detection and Cleanup

Before applying migrations that enforce database-level partial unique indexes on `asset_device_links`, ensure no duplicate ACTIVE links exist.
Run the detection tool from the repository root:

```bash
python tools/find_duplicate_links.py
```

If duplicate ACTIVE links are detected, follow this remediation procedure:
1. Identify the conflicting device IDs and asset IDs listed in the tool output.
2. For each conflict, consult physical inventory records to determine which link reflects the current physical placement.
3. For obsolete active links, close the relationship in the database by setting `relationship_status = 'CLOSED'`, `unlinked_at = NOW()`, and `reason = 'Manual resolution of duplicate active links prior to hardening migration'`.
4. Re-run `python tools/find_duplicate_links.py` to confirm that zero duplicate ACTIVE links remain.
5. Apply database migrations using `flask db upgrade`.
