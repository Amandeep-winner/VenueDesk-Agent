# VenueDesk Agent Pilot Deployment & Verification Checklist

## Pre-Deployment Verification

- [ ] Control plane backend running with production PostgreSQL database.
- [ ] Alembic schema migrations verified up to head (`python tools/test_migration_on_copy.py`).
- [ ] TLS certificates deployed and valid for control plane URL (`https://...`).
- [ ] Secret keys and deployment salt configured via secure environment variables.
- [ ] Initial asset records seeded for pilot machines in `DRAFT` or `ASSIGNED` state.
- [ ] Dedicated administrative account created for lab manager.

## Machine Setup & Initial Enrollment

### Machine 1: PC-PILOT-01 (Baseline Desktop)
- [ ] Run installer: `sudo ./install.sh --server <URL> --token <TOKEN>` (or `install.ps1`).
- [ ] Verify agent service status: `systemctl status venuedesk-agent` / `Get-Service VenueDeskAgent`.
- [ ] Verify local agent health: `venuedesk-agent status`.
- [ ] Check control plane UI: device listed as `ACTIVE` and paired to asset tag `VD-ASSET-000421`.
- [ ] Inspect telemetry charts: CPU, memory, and disk percent rendering accurately.

### Machine 2: PC-PILOT-02 (Identical Desktop)
- [ ] Generate distinct pairing token for `VD-ASSET-000422`.
- [ ] Run installer on second identical hardware unit.
- [ ] Confirm device ID is distinct from PC-PILOT-01.
- [ ] Confirm no duplicate active link constraint errors occurred in database.

### Machine 3: PC-PILOT-03 (Hardware Change Simulation)
- [ ] Verify initial baseline inventory in control plane.
- [ ] Perform hardware swap (e.g. secondary GPU, RAM module, or network adapter).
- [ ] Restart agent and trigger collection cycle: `venuedesk-agent collect-once`.
- [ ] Confirm control plane creates a `HardwareChangeRecord`.
- [ ] Verify admin dashboard displays change details in verification queue.
- [ ] Admin clicks "Approve Hardware Change" with typed reason.
- [ ] Confirm audit log captures approving actor and timestamps.

### Machine 4: PC-PILOT-04 (Dual-Boot Setup)
- [ ] Boot Windows: run `install.ps1` with primary pairing token.
- [ ] Confirm primary OS installation registered in admin device detail view.
- [ ] In admin UI, click "Generate OS Token" for this device.
- [ ] Reboot into Linux: run `install.sh` with the device-scoped OS token.
- [ ] Confirm single physical device now lists two `OSInstallation` records.
- [ ] Alternate OS boot and verify both environments successfully send heartbeats.

### Machine 5: PC-PILOT-05 (Offline Resilience)
- [ ] Disconnect network cable / disable network adapter for 2 hours.
- [ ] Inspect agent logs: outbox enqueues telemetry and enters backoff loop.
- [ ] Reconnect network.
- [ ] Verify queue drains in order: identity events first, inventory second, telemetry third.
- [ ] Run `SELECT count(*) FROM processed_events;` on server to verify 0 duplicate ingestion.

### Machine 6: PC-PILOT-06 (OS Reinstall & Recovery)
- [ ] Delete agent state dir to simulate disk wipe / fresh OS installation.
- [ ] Execute recovery command: `venuedesk-agent recover --server <URL> --wait`.
- [ ] Verify status moves to `pending_approval`.
- [ ] Open web dashboard: navigate to Verification Queue -> Recovery Requests.
- [ ] Review matching hardware anchors and click "Approve Recovery".
- [ ] Verify agent command completes, new credentials take effect, and device returns to `ACTIVE`.

## Daily Pilot Inspection Routine

- [ ] Run link audit script: `python tools/find_duplicate_links.py`.
- [ ] Review system audit trail for unexpected errors: `/admin/infrastructure/audit`.
- [ ] Check outbox dropped counters across active agents.
- [ ] Verify heartbeat timestamps: no pilot machines marked `OFFLINE` unexpectedly.
- [ ] Run database integrity check: `python tools/test_migration_on_copy.py`.
