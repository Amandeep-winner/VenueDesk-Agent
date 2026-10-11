"""Admin device management and inspection API endpoints."""
from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from app.extensions import db
from app.models import DeviceStatus, PhysicalDevice, UserRole
from app.security.rbac import require_role
from app.services.identity_service import approve_hardware_change, pair_unclaimed_device
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

    try:
        dev, asset = pair_unclaimed_device(device_id, asset_id, admin_name=admin_name)
        return jsonify({
            "status": "paired",
            "device_id": dev.device_id,
            "asset_id": asset.asset_id,
            "device_status": dev.status.value,
        }), 200
    except ValueError as exc:
        return jsonify({"error": "bad_request", "message": str(exc)}), 400
