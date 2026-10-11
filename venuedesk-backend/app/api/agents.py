"""Agent-facing control plane API endpoints."""
import time
from collections import defaultdict

from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import ActorType, AuditAction, AuditLog
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
