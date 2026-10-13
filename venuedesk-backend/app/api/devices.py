"""Admin device management and inspection API endpoints."""
from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from app.extensions import db
from app.models import DeviceRecoveryRequest, DeviceStatus, PhysicalDevice, UserRole
from app.security.rbac import require_role
from app.services.identity_service import (
    LinkConflictError,
    approve_device_recovery,
    approve_hardware_change,
    pair_device,
    replace_device_endpoint,
    verify_device_physical,
)
from app.services.telemetry_service import get_device_telemetry

devices_bp = Blueprint("devices", __name__, url_prefix="/api/v1/admin/devices")


def _find_device(device_identifier: str) -> PhysicalDevice | None:
    """Find device by device_id (VD-DEVICE-...) or primary key."""
    dev = PhysicalDevice.query.filter_by(device_id=device_identifier).first()
    if dev:
        return dev
    try:
        pk = int(device_identifier)
        return db.session.get(PhysicalDevice, pk)
    except ValueError:
        return None


def _parse_query_dt(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        clean_str = dt_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


@devices_bp.route("/<device_id>/telemetry", methods=["GET"])
@require_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def get_telemetry_endpoint(device_id: str):
    """Retrieve telemetry metrics time series for an endpoint."""
    device = _find_device(device_id)
    if not device:
        return jsonify({"error": "not_found", "message": f"Device {device_id} not found"}), 404

    from_dt = _parse_query_dt(request.args.get("from"))
    to_dt = _parse_query_dt(request.args.get("to"))
    limit = 100
    if "limit" in request.args:
        try:
            limit = int(request.args["limit"])
        except ValueError:
            pass

    records = get_device_telemetry(device.id, from_time=from_dt, to_time=to_dt, limit=limit)
    return jsonify({
        "device_id": device.device_id,
        "count": len(records),
        "telemetry": records,
    }), 200


@devices_bp.route("/<device_id>/approve-hardware-change", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def approve_hardware_change_endpoint(device_id: str):
    """Approve observed hardware changes, marking latest snapshot trusted and restoring ACTIVE status."""
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"
    try:
        dev = approve_hardware_change(device_id, admin_name=admin_name)
        return jsonify({
            "status": "approved",
            "device_id": dev.device_id,
            "device_status": dev.status.value,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "not_found", "message": str(exc)}), 404


@devices_bp.route("/unclaimed", methods=["GET"])
@require_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def get_unclaimed_devices_endpoint():
    """Retrieve list of devices in UNCLAIMED status."""
    unclaimed = PhysicalDevice.query.filter_by(status=DeviceStatus.UNCLAIMED).all()
    res = []
    for d in unclaimed:
        inv = d.inventory
        res.append({
            "device_id": d.device_id,
            "status": d.status.value,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "hostname": inv.hostname if inv else "unknown",
            "ip_addresses": inv.ip_addresses if inv else [],
        })
    return jsonify({"count": len(res), "devices": res}), 200


@devices_bp.route("/<device_id>/pair", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def pair_device_endpoint(device_id: str):
    """Pair an unclaimed device to an institutional asset."""
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"
    payload = request.get_json(silent=True) or {}
    asset_id = payload.get("asset_id")

    if not asset_id:
        return jsonify({"error": "invalid_payload", "message": "Missing 'asset_id' in payload"}), 400

    reassignment = bool(payload.get("reassignment", False))
    reason = payload.get("reason")

    try:
        dev, asset, _link = pair_device(
            device_identifier=device_id,
            asset_identifier=asset_id,
            admin_name=admin_name,
            actor_role=UserRole.INFRA_ADMIN,
            reassignment=reassignment,
            reason=reason,
        )
        return jsonify({
            "status": "paired",
            "device_id": dev.device_id,
            "asset_id": asset.asset_id,
            "device_status": dev.status.value,
        }), 200
    except LinkConflictError as exc:
        return jsonify({"error": "link_conflict", "message": str(exc)}), 409
    except ValueError as exc:
        return jsonify({"error": "bad_request", "message": str(exc)}), 400


@devices_bp.route("/<device_id>/approve-recovery", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def approve_recovery_endpoint(device_id: str):
    """Approve a pending OS reinstall recovery request for an endpoint."""
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"
    try:
        dev, rec_req = approve_device_recovery(device_id, admin_name=admin_name)
        return jsonify({
            "status": "approved",
            "device_id": dev.device_id,
            "credential_version": dev.credential_version,
            "device_status": dev.status.value,
            "recovery_request_id": rec_req.id,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "not_found", "message": str(exc)}), 404


@devices_bp.route("/<device_id>/verify", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def verify_device_endpoint(device_id: str):
    """Perform physical verification of device-to-asset continuity."""
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"
    payload = request.get_json(silent=True) or {}

    verification_method = payload.get("verification_method", "ADMIN_CONFIRMATION")
    observed_asset_tag = payload.get("observed_asset_tag")
    observed_serial = payload.get("observed_serial")
    observed_location = payload.get("observed_location")
    notes = payload.get("notes")

    try:
        dev, asset, ver = verify_device_physical(
            device_id,
            admin_name=admin_name,
            verification_method=verification_method,
            observed_asset_tag=observed_asset_tag,
            observed_serial=observed_serial,
            observed_location=observed_location,
            notes=notes,
        )
        return jsonify({
            "status": "verified",
            "device_id": dev.device_id,
            "asset_id": asset.asset_id if asset else None,
            "verification_id": ver.id,
            "device_status": dev.status.value,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "not_found", "message": str(exc)}), 404


@devices_bp.route("/<device_id>/replace-endpoint", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def replace_endpoint_endpoint(device_id: str):
    """Replace an endpoint hardware/motherboard: retires old device, closes link, and generates new token for asset."""
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"
    payload = request.get_json(silent=True) or {}
    reason = payload.get("reason", "Endpoint hardware/motherboard replacement")

    try:
        dev, asset, raw_token, token_obj = replace_device_endpoint(
            device_id,
            admin_name=admin_name,
            reason=reason,
        )
        return jsonify({
            "status": "endpoint_replaced",
            "old_device_id": dev.device_id,
            "asset_id": asset.asset_id,
            "new_pairing_token": raw_token,
            "expires_at": token_obj.expires_at.isoformat() if token_obj.expires_at else None,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "bad_request", "message": str(exc)}), 400


@devices_bp.route("/recovery-requests", methods=["GET"])
@require_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def get_recovery_requests_endpoint():
    """Retrieve list of pending device recovery requests."""
    status_filter = request.args.get("status", "PENDING").upper()
    reqs = (
        DeviceRecoveryRequest.query.filter_by(status=status_filter)
        .order_by(DeviceRecoveryRequest.created_at.desc())
        .all()
    )
    result = []
    for r in reqs:
        result.append({
            "id": r.id,
            "device_id": r.device.device_id if r.device else None,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "new_agent_instance_id": r.new_agent_instance_id,
        })
    return jsonify({"count": len(result), "recovery_requests": result}), 200


@devices_bp.route("/<device_id>/jobs", methods=["POST"])
@require_role(UserRole.INFRA_ADMIN)
def create_device_job_endpoint(device_id: str):
    """Dispatch an allowlisted remote maintenance or diagnostic job to an endpoint."""
    device = _find_device(device_id)
    if not device:
        return jsonify({"error": "not_found", "message": f"Device {device_id} not found"}), 404

    payload = request.get_json(silent=True) or {}
    job_type = payload.get("job_type")
    if not job_type:
        return jsonify({"error": "invalid_payload", "message": "Missing 'job_type' field"}), 400

    job_payload = payload.get("payload", {})
    expires_in = payload.get("expires_in_seconds", 3600)
    admin_name = getattr(g, "current_user", None).username if getattr(g, "current_user", None) else "admin"

    try:
        from app.services import job_service
        job = job_service.create_job(
            device_identifier=device.id,
            job_type=job_type,
            payload=job_payload,
            created_by=admin_name,
            expires_in_seconds=int(expires_in),
        )
        return jsonify({
            "status": "dispatched",
            "job_id": job.id,
            "device_id": device.device_id,
            "job_type": job.job_type.value,
            "job_status": job.status.value,
            "expires_at": job.expires_at.isoformat(),
        }), 201
    except ValueError as exc:
        return jsonify({"error": "invalid_job", "message": str(exc)}), 400


@devices_bp.route("/<device_id>/jobs", methods=["GET"])
@require_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def get_device_jobs_endpoint(device_id: str):
    """Retrieve remote job history and results for an endpoint."""
    device = _find_device(device_id)
    if not device:
        return jsonify({"error": "not_found", "message": f"Device {device_id} not found"}), 404

    from app.services import job_service
    jobs = job_service.get_device_jobs(device.id)
    results = [
        {
            "id": j.id,
            "job_type": j.job_type.value,
            "status": j.status.value,
            "payload": j.payload,
            "created_by": j.created_by,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            "expires_at": j.expires_at.isoformat() if j.expires_at else None,
            "result": j.result,
        }
        for j in jobs
    ]
    return jsonify({
        "device_id": device.device_id,
        "count": len(results),
        "jobs": results,
    }), 200

