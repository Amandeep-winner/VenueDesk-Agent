"""Admin device management and inspection API endpoints."""
from datetime import UTC, datetime

from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import PhysicalDevice, UserRole
from app.security.rbac import require_role
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
