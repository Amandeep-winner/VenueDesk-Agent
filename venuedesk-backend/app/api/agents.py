"""Agent-facing control plane API endpoints."""
import time
from collections import defaultdict
from datetime import UTC, datetime

from flask import Blueprint, current_app, g, jsonify, request

from app.extensions import db
from app.models import (
    ActorType,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EventSeverity,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
)
from app.security.signatures import require_device_auth, verify
from app.services.enrollment_service import enroll_agent
from app.services.identity_service import LinkConflictError

agents_bp = Blueprint("agents", __name__, url_prefix="/api/v1/agents")

_enroll_attempts: dict[str, list[float]] = defaultdict(list)


def check_enroll_rate_limit(ip: str, max_attempts: int = 10, window_seconds: int = 60) -> bool:
    """Check if IP has exceeded enrollment rate limits (default 10/min)."""
    now = time.time()
    attempts = [t for t in _enroll_attempts[ip] if now - t < window_seconds]
    if len(attempts) >= max_attempts:
        return False
    attempts.append(now)
    _enroll_attempts[ip] = attempts
    return True


def reset_rate_limits() -> None:
    """Clear in-memory rate limiting counters (for testing)."""
    _enroll_attempts.clear()


@agents_bp.route("/enroll", methods=["POST"])
def enroll():
    """Enroll endpoint with the control plane (token or unclaimed mode)."""
    source_ip = request.remote_addr or "127.0.0.1"

    if not check_enroll_rate_limit(source_ip):
        return jsonify({
            "error": "rate_limited",
            "message": "Too many enrollment attempts. Please try again later.",
        }), 429

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "invalid_payload", "message": "JSON body is required"}), 400

    try:
        res = enroll_agent(payload, source_ip=source_ip)
        return jsonify(res), 200
    except PermissionError as exc:
        return jsonify({"error": "unclaimed_enrollment_disabled", "message": str(exc)}), 403
    except LinkConflictError as exc:
        db.session.rollback()
        return jsonify({"error": "invalid_enrollment_token", "message": str(exc)}), 400
    except ValueError as exc:
        # Audit failed enrollment attempt
        try:
            db.session.add(
                AuditLog(
                    actor_id=source_ip,
                    actor_type=ActorType.SYSTEM,
                    action=AuditAction.DEVICE_ENROLLED,
                    entity_type="enrollment_failure",
                    entity_id="unauthorized",
                    metadata_json={"error": str(exc)},
                    ip_address=source_ip,
                )
            )
            db.session.commit()
        except (db.exc.SQLAlchemyError, OSError):
            db.session.rollback()

        return jsonify({"error": "invalid_enrollment", "message": str(exc)}), 400


@agents_bp.route("/recover", methods=["POST"])
def recover():
    """Endpoint recovery workflow following OS reinstall or state loss (spec §4.8)."""
    source_ip = request.remote_addr or "127.0.0.1"

    if not check_enroll_rate_limit(source_ip):
        return jsonify({
            "error": "rate_limited",
            "message": "Too many recovery attempts. Please try again later.",
        }), 429

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "invalid_payload", "message": "JSON body is required"}), 400

    pub_key_b64 = payload.get("device_public_key")
    pop_sig_b64 = payload.get("proof_of_possession")
    req_ts = payload.get("timestamp")
    nonce = payload.get("nonce")

    if not all([pub_key_b64, pop_sig_b64, req_ts, nonce]):
        return jsonify({"error": "invalid_payload", "message": "Missing required cryptographic parameters"}), 400

    try:
        req_ts_int = int(req_ts)
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_timestamp", "message": "Invalid timestamp format"}), 400

    skew_limit = current_app.config.get("CLOCK_SKEW_SECONDS", 120)
    current_ts = int(time.time())
    if abs(current_ts - req_ts_int) > skew_limit:
        return jsonify({"error": "clock_skew", "message": "Timestamp out of allowable skew window"}), 400

    nonce_key = f"recover-{source_ip}-{pub_key_b64[:16]}"
    from app.security.replay import check_and_record_nonce
    if not check_and_record_nonce(nonce_key, str(nonce), skew_seconds=skew_limit):
        return jsonify({"error": "replay_detected", "message": "Nonce replayed"}), 400

    msg = f"recover\n{pub_key_b64}\n{req_ts}\n{nonce}".encode()
    if not verify(pub_key_b64, pop_sig_b64, msg):
        return jsonify({"error": "invalid_signature", "message": "Cryptographic proof of possession failed"}), 400

    from app.services.identity_service import (
        IdentityDecision,
        Observation,
        determine_device_identity,
    )
    obs = Observation(
        device_public_key=pub_key_b64,
        evidence=payload.get("identity_evidence", {}),
        inventory=payload.get("inventory"),
        os=payload.get("os"),
        agent_instance_id=payload.get("agent_instance_id"),
    )
    decision, candidates, score = determine_device_identity(obs)

    now = datetime.now(UTC)
    if decision == IdentityDecision.PENDING_REVERIFICATION:
        candidate = candidates[0]
        candidate.status = DeviceStatus.PENDING_REVERIFICATION

        event = DeviceEvent(
            device_id=candidate.id,
            event_type=DeviceEventType.OS_REINSTALL_DETECTED,
            severity=EventSeverity.HIGH,
            payload={
                "message": "OS reinstall detected via strong hardware evidence",
                "similarity_score": score,
                "new_agent_instance_id": payload.get("agent_instance_id"),
            },
            occurred_at=now,
            created_at=now,
        )
        db.session.add(event)

        from app.models import DeviceRecoveryRequest
        rec_req = DeviceRecoveryRequest(
            device_id=candidate.id,
            new_public_key=pub_key_b64,
            new_agent_instance_id=payload.get("agent_instance_id") or "unknown",
            new_os_info=payload.get("os"),
            new_inventory=payload.get("inventory"),
            new_evidence=payload.get("identity_evidence"),
            status="PENDING",
            created_at=now,
        )
        db.session.add(rec_req)
        db.session.commit()

        return jsonify({
            "status": "pending_approval",
            "device_id": candidate.device_id,
            "recovery_request_id": rec_req.id,
            "message": "Recovery request pending administrator approval",
        }), 200

    elif decision == IdentityDecision.UNKNOWN_DEVICE:
        return jsonify({"error": "unknown_device", "message": "No matching device found for recovery"}), 404

    elif decision == IdentityDecision.AMBIGUOUS:
        return jsonify({"error": "ambiguous_match", "message": "Multiple candidate devices matched evidence"}), 409

    else:
        return jsonify({
            "error": "manual_verification_required",
            "message": "Insufficient matching anchors for automatic recovery",
        }), 400


@agents_bp.route("/recover/status", methods=["GET"])
def recover_status():
    """Poll endpoint recovery approval status."""
    device_id = request.args.get("device_id") or request.headers.get("X-Device-ID")
    if not device_id:
        return jsonify({"error": "missing_parameter", "message": "device_id query param or header required"}), 400

    from app.models import DeviceRecoveryRequest, PhysicalDevice
    device = PhysicalDevice.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "not_found", "message": f"Device {device_id} not found"}), 404

    rec_req = (
        DeviceRecoveryRequest.query.filter_by(device_id=device.id)
        .order_by(DeviceRecoveryRequest.created_at.desc())
        .first()
    )
    if not rec_req:
        return jsonify({"status": "none", "device_id": device.device_id}), 200

    if rec_req.status == "APPROVED":
        return jsonify({
            "status": "approved",
            "device_id": device.device_id,
            "credential_version": device.credential_version,
            "config": {
                "heartbeat_seconds": current_app.config.get("HEARTBEAT_SECONDS", 60),
                "telemetry_seconds": current_app.config.get("TELEMETRY_SECONDS", 60),
                "inventory_seconds": current_app.config.get("INVENTORY_SECONDS", 21600),
                "jobs_poll_seconds": current_app.config.get("JOBS_POLL_SECONDS", 60),
            },
        }), 200

    if rec_req.status == "REJECTED":
        return jsonify({"status": "rejected", "device_id": device.device_id}), 200

    return jsonify({"status": "pending", "device_id": device.device_id}), 200


@agents_bp.route("/heartbeat", methods=["POST"])
@require_device_auth
def heartbeat():
    """Process device-authenticated heartbeat and perform duplicate device detection."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}
    now = datetime.now(UTC)

    # Duplicate device detection (§4.9)
    inst_id = payload.get("agent_instance_id")
    if inst_id:
        active_os = OSInstallation.query.filter_by(
            device_id=device.id,
            status=OsInstallationStatus.ACTIVE,
        ).all()
        known_inst_ids = {os_inst.agent_instance_id for os_inst in active_os}

        if known_inst_ids and inst_id not in known_inst_ids:
            dup_window = current_app.config.get("DUPLICATE_WINDOW_SECONDS", 120)
            if device.last_seen:
                last_seen_dt = device.last_seen if device.last_seen.tzinfo else device.last_seen.replace(tzinfo=UTC)
                if (now - last_seen_dt).total_seconds() <= dup_window:
                    # Duplicate device detected -> suspend device immediately
                    device.status = DeviceStatus.SUSPENDED
                    event = DeviceEvent(
                        device_id=device.id,
                        event_type=DeviceEventType.DUPLICATE_DEVICE_IDENTITY,
                        severity=EventSeverity.CRITICAL,
                        payload={
                            "message": "Heartbeat from unexpected agent_instance_id within active window",
                            "observed_instance_id": inst_id,
                            "registered_instance_ids": sorted(known_inst_ids),
                        },
                        occurred_at=now,
                        created_at=now,
                    )
                    db.session.add(event)
                    db.session.add(
                        AuditLog(
                            actor_id=device.device_id,
                            actor_type=ActorType.DEVICE,
                            action=AuditAction.IDENTITY_OVERRIDE,
                            entity_type="device",
                            entity_id=device.device_id,
                            new_value={"status": DeviceStatus.SUSPENDED.value},
                            metadata_json={"reason": "DUPLICATE_DEVICE_IDENTITY"},
                        )
                    )
                    db.session.commit()
                    return jsonify({
                        "error": "device_suspended",
                        "message": "Duplicate device identity detected. Endpoint suspended.",
                    }), 403

    # Recover OFFLINE device back to ACTIVE on valid heartbeat
    if device.status == DeviceStatus.OFFLINE:
        device.status = DeviceStatus.ACTIVE

    device.last_seen = now
    db.session.commit()

    from app.services.job_service import has_pending_jobs
    pending = has_pending_jobs(device.id)

    return jsonify({
        "server_time": int(now.timestamp()),
        "config_version": 1,
        "pending_jobs": pending,
    }), 200


@agents_bp.route("/config", methods=["GET"])
@require_device_auth
def get_config():
    """Return control-plane configuration and collection intervals."""
    return jsonify({
        "heartbeat_seconds": current_app.config.get("HEARTBEAT_SECONDS", 60),
        "telemetry_seconds": current_app.config.get("TELEMETRY_SECONDS", 60),
        "inventory_seconds": current_app.config.get("INVENTORY_SECONDS", 21600),
        "jobs_poll_seconds": current_app.config.get("JOBS_POLL_SECONDS", 60),
        "config_version": 1,
    }), 200


@agents_bp.route("/rotate-credential", methods=["POST"])
@require_device_auth
def rotate_credential():
    """Rotate endpoint public key signed by the existing authorized private key."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}

    new_pub_key = payload.get("new_public_key")
    sig_by_old = payload.get("signature_by_old_key")
    ts = payload.get("timestamp")

    if not all([new_pub_key, sig_by_old, ts]):
        return jsonify({"error": "invalid_payload", "message": "Missing rotation parameters"}), 400

    msg = f"rotate\n{device.device_id}\n{new_pub_key}\n{ts}".encode()
    if not verify(device.device_public_key, sig_by_old, msg):
        return jsonify({"error": "invalid_rotation_signature", "message": "Old key signature verification failed"}), 400

    # Advance credential version and store new public key
    old_ver = device.credential_version
    device.device_public_key = new_pub_key
    device.credential_version = old_ver + 1

    db.session.add(
        AuditLog(
            actor_id=device.device_id,
            actor_type=ActorType.DEVICE,
            action=AuditAction.CREDENTIAL_ROTATED,
            entity_type="device",
            entity_id=device.device_id,
            old_value={"credential_version": old_ver},
            new_value={"credential_version": device.credential_version},
        )
    )
    db.session.commit()

    return jsonify({
        "status": "rotated",
        "credential_version": device.credential_version,
    }), 200


@agents_bp.route("/inventory", methods=["POST"])
@require_device_auth
def post_inventory():
    """Update observed endpoint technical inventory snapshot and OS installation."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}
    inv_data = payload.get("inventory") or payload
    os_data = payload.get("os")

    # Trigger reconciliation hook before updating current snapshot
    try:
        from app.services.identity_service import reconcile_device_inventory
        reconcile_device_inventory(device, inv_data, os_data)
    except (ImportError, AttributeError):
        pass

    inv = DeviceInventory.query.filter_by(device_id=device.id).first()
    if not inv:
        inv = DeviceInventory(
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
            tpm_present=bool(inv_data.get("tpm_present", False)),
            agent_version=inv_data.get("agent_version", "0.1.0"),
            updated_at=datetime.now(UTC),
        )
        db.session.add(inv)
    else:
        if "hostname" in inv_data:
            inv.hostname = inv_data["hostname"]
        if "ip_addresses" in inv_data:
            inv.ip_addresses = inv_data["ip_addresses"]
        if "mac_addresses" in inv_data:
            inv.mac_addresses = inv_data["mac_addresses"]
        if "cpu_model" in inv_data:
            inv.cpu_model = inv_data["cpu_model"]
        if "cpu_cores" in inv_data:
            inv.cpu_cores = inv_data["cpu_cores"]
        if "ram_total_mb" in inv_data:
            inv.ram_total_mb = inv_data["ram_total_mb"]
        if "gpus" in inv_data:
            inv.gpus = inv_data["gpus"]
        if "disks" in inv_data:
            inv.disks = inv_data["disks"]
        if "os_summary" in inv_data:
            inv.os_summary = inv_data["os_summary"]
        if "bios_version" in inv_data:
            inv.bios_version = inv_data["bios_version"]
        if "tpm_present" in inv_data:
            inv.tpm_present = bool(inv_data["tpm_present"])
        if "agent_version" in inv_data:
            inv.agent_version = inv_data["agent_version"]
        inv.updated_at = datetime.now(UTC)

    now = datetime.now(UTC)
    if os_data and isinstance(os_data, dict):
        raw_fam = (os_data.get("family") or "OTHER").upper()
        try:
            os_fam = OsFamily(raw_fam)
        except ValueError:
            os_fam = OsFamily.OTHER

        m_hash = os_data.get("os_machine_id_hash", "unknown")
        os_inst = OSInstallation.query.filter_by(
            device_id=device.id,
            os_family=os_fam,
            os_machine_id_hash=m_hash,
        ).first()

        if not os_inst:
            os_inst = OSInstallation(
                device_id=device.id,
                os_family=os_fam,
                os_name=os_data.get("name", "Unknown"),
                os_version=os_data.get("version", "Unknown"),
                architecture=os_data.get("architecture", "Unknown"),
                os_machine_id_hash=m_hash,
                agent_instance_id=payload.get("agent_instance_id") or os_data.get("agent_instance_id") or "unknown",
                first_seen=now,
                last_seen=now,
                status=OsInstallationStatus.ACTIVE,
            )
            db.session.add(os_inst)
        else:
            os_inst.os_name = os_data.get("name", os_inst.os_name)
            os_inst.os_version = os_data.get("version", os_inst.os_version)
            os_inst.architecture = os_data.get("architecture", os_inst.architecture)
            os_inst.last_seen = now
            os_inst.status = OsInstallationStatus.ACTIVE

    device.last_seen = now
    db.session.commit()

    return jsonify({"status": "inventory_updated"}), 200


@agents_bp.route("/telemetry", methods=["POST"])
@require_device_auth
def post_telemetry():
    """Ingest batch telemetry metrics (max 500 samples per batch)."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}

    samples = payload.get("samples")
    if samples is None:
        if isinstance(payload, list):
            samples = payload
        else:
            return jsonify({"error": "invalid_payload", "message": "Expected 'samples' list in payload"}), 400

    if not isinstance(samples, list):
        return jsonify({"error": "invalid_payload", "message": "'samples' must be a list"}), 400

    if len(samples) > 500:
        return jsonify({
            "error": "payload_too_large",
            "message": f"Telemetry batch exceeds maximum limit of 500 samples (received {len(samples)})",
        }), 413

    from app.services.telemetry_service import record_telemetry
    count = record_telemetry(device.id, samples)
    return jsonify({"status": "recorded", "count": count}), 200


@agents_bp.route("/identity", methods=["POST"])
@require_device_auth
def post_identity():
    """Submit updated device identity evidence snapshot."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}
    ev_data = payload.get("identity_evidence") or payload

    now = datetime.now(UTC)
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
    device.last_seen = now
    db.session.commit()

    # Trigger reconciliation hook if identity service is available
    try:
        from app.services.identity_service import reconcile_device_evidence
        reconcile_device_evidence(device, ev_data)
    except (ImportError, AttributeError):
        pass

    return jsonify({"status": "identity_received"}), 200


@agents_bp.route("/jobs", methods=["GET"])
@agents_bp.route("/jobs/poll", methods=["POST"])
@require_device_auth
def poll_jobs():
    """Poll pending remote maintenance/diagnostic jobs dispatched to this device."""
    device = g.current_device
    from app.services.job_service import get_pending_jobs_for_device

    jobs = get_pending_jobs_for_device(device.id, mark_dispatched=True)
    return jsonify({
        "jobs": [
            {
                "id": j.id,
                "job_type": j.job_type.value,
                "payload": j.payload,
                "expires_at": j.expires_at.isoformat() if j.expires_at else None,
            }
            for j in jobs
        ]
    }), 200


@agents_bp.route("/jobs/<int:job_id>/result", methods=["POST"])
@require_device_auth
def post_job_result(job_id: int):
    """Report execution outcome and payload results for a dispatched job."""
    device = g.current_device
    payload = request.get_json(silent=True) or {}

    status = payload.get("status", "FAILED")
    result_data = payload.get("result")
    error_msg = payload.get("error")

    from app.services.job_service import record_job_result

    try:
        job = record_job_result(
            job_id=job_id,
            device_identifier=device.id,
            status=status,
            result=result_data,
            error=error_msg,
        )
        return jsonify({
            "status": "recorded",
            "job_id": job.id,
            "job_status": job.status.value,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "invalid_job", "message": str(exc)}), 400

