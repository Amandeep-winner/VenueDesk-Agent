"""Enrollment service handling agent registration, proof-of-possession, and device-asset linking."""
import hashlib
import time
from datetime import UTC, datetime

from flask import current_app

from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EndpointType,
    EventSeverity,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    generate_device_id,
)
from app.security.replay import check_and_record_nonce
from app.security.signatures import verify
from app.security.tokens import consume_token_atomically


def enroll_agent(payload: dict, source_ip: str) -> dict:
    """Enroll endpoint with VenueDesk control plane via pairing token or unclaimed mode."""
    # 1. Extract required payload fields
    token_str = payload.get("enrollment_token")
    pub_key_b64 = payload.get("device_public_key")
    pop_sig_b64 = payload.get("proof_of_possession")
    req_ts = payload.get("timestamp")
    nonce = payload.get("nonce")

    if not all([pub_key_b64, pop_sig_b64, req_ts, nonce]):
        raise ValueError("Missing required cryptographic enrollment parameters")

    try:
        req_ts_int = int(req_ts)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid timestamp format") from exc

    # 2. Clock skew verification
    skew_limit = current_app.config.get("CLOCK_SKEW_SECONDS", 120)
    current_ts = int(time.time())
    if abs(current_ts - req_ts_int) > skew_limit:
        raise ValueError("Enrollment timestamp out of allowable clock skew window")

    # 3. Nonce replay defense (keyed by source_ip + public key prefix)
    nonce_key = f"enroll-{source_ip}-{pub_key_b64[:16]}"
    if not check_and_record_nonce(nonce_key, str(nonce), skew_seconds=skew_limit):
        raise ValueError("Enrollment nonce replayed or duplicate")

    # 4. Proof of possession signature verification
    token_sha256 = hashlib.sha256(token_str.strip().encode("utf-8")).hexdigest() if token_str else ""
    msg = f"enroll\n{token_sha256}\n{req_ts}\n{nonce}".encode()
    if not verify(pub_key_b64, pop_sig_b64, msg):
        raise ValueError("Cryptographic proof of possession verification failed")

    # 5. Token validation or Unclaimed Mode check
    now = datetime.now(UTC)
    asset = None
    token_row = None

    if token_str:
        token_row = consume_token_atomically(token_str)
        asset = db.session.get(Asset, token_row.asset_id)
        if not asset:
            raise ValueError(f"Associated asset ID {token_row.asset_id} not found")
    else:
        allow_unclaimed = current_app.config.get("ALLOW_UNCLAIMED_ENROLLMENT", False)
        if not allow_unclaimed:
            raise PermissionError("Unclaimed device enrollment is disabled on this server")

    # 6. Generate collision-resistant device ID
    dev_id = generate_device_id()
    while PhysicalDevice.query.filter_by(device_id=dev_id).first() is not None:
        dev_id = generate_device_id()

    device_status = DeviceStatus.PENDING_VERIFICATION if asset else DeviceStatus.UNCLAIMED
    device = PhysicalDevice(
        device_id=dev_id,
        device_public_key=pub_key_b64,
        credential_version=1,
        status=device_status,
        endpoint_type=EndpointType.PHYSICAL,
        first_seen=now,
        last_seen=now,
    )
    db.session.add(device)
    db.session.flush()

    if token_row:
        token_row.used_by_device_id = device.id

    # 7. Create AssetDeviceLink via canonical pair_device function
    if asset:
        from app.services.identity_service import pair_device

        _, _, _link = pair_device(
            device_identifier=device.id,
            asset_identifier=asset.id,
            admin_name="system",
            commit=False,
            _caller="enrollment",
        )

        db.session.add(
            AuditLog(
                actor_id=source_ip,
                actor_type=ActorType.SYSTEM,
                action=AuditAction.DEVICE_ENROLLED,
                entity_type="device",
                entity_id=device.device_id,
                new_value={"status": device.status.value, "asset_id": asset.asset_id},
                ip_address=source_ip,
            )
        )
    else:
        # Unclaimed device audit and event
        db.session.add(
            AuditLog(
                actor_id=source_ip,
                actor_type=ActorType.SYSTEM,
                action=AuditAction.DEVICE_ENROLLED,
                entity_type="device",
                entity_id=device.device_id,
                new_value={"status": device.status.value},
                ip_address=source_ip,
            )
        )
        db.session.add(
            DeviceEvent(
                device_id=device.id,
                event_type=DeviceEventType.UNCLAIMED_DEVICE_DISCOVERED,
                severity=EventSeverity.MEDIUM,
                payload={"message": "Unclaimed device discovered via open enrollment"},
                occurred_at=now,
                created_at=now,
            )
        )

    # 8. Store Hardware Evidence snapshot
    ev_data = payload.get("identity_evidence", {})
    evidence_row = DeviceIdentityEvidence(
        device_id=device.id,
        machine_uuid_hash=ev_data.get("machine_uuid_hash"),
        bios_serial_hash=ev_data.get("bios_serial_hash"),
        motherboard_serial_hash=ev_data.get("motherboard_serial_hash"),
        cpu_signature=ev_data.get("cpu_signature"),
        gpu_signature=ev_data.get("gpu_signature"),
        disk_identity_hash=ev_data.get("disk_identity_hash"),
        network_identity_hash=ev_data.get("network_identity_hash"),
        tpm_identity=ev_data.get("tpm_identity"),
        fingerprint=ev_data.get("fingerprint", "unknown"),
        fingerprint_version=ev_data.get("fingerprint_version", 1),
        captured_at=now,
        evidence_version=1,
        trusted=False,
    )
    db.session.add(evidence_row)

    # 9. Store OS installation
    os_data = payload.get("os", {})
    raw_family = (os_data.get("family") or "OTHER").upper()
    try:
        os_fam = OsFamily(raw_family)
    except ValueError:
        os_fam = OsFamily.OTHER

    os_inst = OSInstallation(
        device_id=device.id,
        os_family=os_fam,
        os_name=os_data.get("name", "Unknown"),
        os_version=os_data.get("version", "Unknown"),
        architecture=os_data.get("architecture", "Unknown"),
        os_machine_id_hash=os_data.get("os_machine_id_hash", "Unknown"),
        agent_instance_id=payload.get("agent_instance_id", "Unknown"),
        first_seen=now,
        last_seen=now,
        status=OsInstallationStatus.ACTIVE,
    )
    db.session.add(os_inst)

    # 10. Store inventory snapshot
    inv_data = payload.get("inventory", {})
    inventory_row = DeviceInventory(
        device_id=device.id,
        hostname=inv_data.get("hostname", "unknown"),
        ip_addresses=inv_data.get("ip_addresses", []),
        mac_addresses=inv_data.get("mac_addresses", []),
        cpu_model=inv_data.get("cpu_model"),
        cpu_cores=inv_data.get("cpu_cores"),
        ram_total_mb=inv_data.get("ram_total_mb"),
        gpus=inv_data.get("gpus", []),
        disks=inv_data.get("disks", []),
        os_summary=inv_data.get("os_summary"),
        bios_version=inv_data.get("bios_version"),
        tpm_present=inv_data.get("tpm_present", False),
        agent_version=payload.get("agent_version", "0.1.0"),
        updated_at=now,
    )
    db.session.add(inventory_row)

    db.session.commit()

    return {
        "device_id": device.device_id,
        "asset_id": asset.asset_id if asset else None,
        "status": device.status.value,
        "credential": {
            "type": "public_key_registered",
            "credential_version": 1,
        },
        "config": {
            "heartbeat_seconds": 60,
            "telemetry_seconds": 60,
            "inventory_seconds": 21600,
            "jobs_poll_seconds": 60,
        },
    }
