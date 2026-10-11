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
    DeviceStatus,
    EventSeverity,
    OSInstallation,
    OsInstallationStatus,
)
from app.security.signatures import require_device_auth, verify
from app.services.enrollment_service import enroll_agent

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

    return jsonify({
        "server_time": int(now.timestamp()),
        "config_version": 1,
        "pending_jobs": False,
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
