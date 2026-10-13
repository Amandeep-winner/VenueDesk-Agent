"""Centralized per-endpoint per-state access policy and enforcement."""
import functools
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from flask import current_app, g, jsonify, request

from app.models import DeviceStatus, PhysicalDevice, UserRole
from app.security.replay import check_and_record_nonce
from app.security.signatures import canonical_string, verify

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Policy:
    """Security policy definition for an endpoint."""

    auth: str  # "device", "role", "token_or_unclaimed_flag", "none+evidence", "device_or_query", "none"
    states: set[DeviceStatus] = field(default_factory=set)
    roles: set[UserRole] = field(default_factory=set)
    rate_limit: str | None = None


# Device states per the matrix in Hardening instructions
HEARTBEAT_STATES = {
    DeviceStatus.ACTIVE,
    DeviceStatus.OFFLINE,
    DeviceStatus.PENDING_VERIFICATION,
    DeviceStatus.PENDING_REVERIFICATION,
}
TELEMETRY_STATES = {DeviceStatus.ACTIVE, DeviceStatus.OFFLINE}
INVENTORY_IDENTITY_CONFIG_STATES = {
    DeviceStatus.ACTIVE,
    DeviceStatus.OFFLINE,
    DeviceStatus.PENDING_VERIFICATION,
    DeviceStatus.PENDING_REVERIFICATION,
}
JOBS_STATES = {DeviceStatus.ACTIVE}
ROTATION_STATES = {DeviceStatus.ACTIVE, DeviceStatus.PENDING_REVERIFICATION}


ENDPOINT_POLICY: dict[str, Policy] = {
    # Agent endpoints
    "agents.enroll": Policy(auth="token_or_unclaimed_flag", rate_limit="10/min"),
    "agents.recover": Policy(auth="none+evidence", rate_limit="10/min"),
    "agents.recover_status": Policy(auth="device_or_query", states={DeviceStatus.PENDING_REVERIFICATION}),
    "agents.heartbeat": Policy(auth="device", states=HEARTBEAT_STATES),
    "agents.get_config": Policy(auth="device", states=INVENTORY_IDENTITY_CONFIG_STATES),
    "agents.rotate_credential": Policy(auth="device", states=ROTATION_STATES),
    "agents.post_inventory": Policy(auth="device", states=INVENTORY_IDENTITY_CONFIG_STATES),
    "agents.post_telemetry": Policy(auth="device", states=TELEMETRY_STATES),
    "agents.post_identity": Policy(auth="device", states=INVENTORY_IDENTITY_CONFIG_STATES),
    "agents.poll_jobs": Policy(auth="device", states=JOBS_STATES),
    "agents.post_job_result": Policy(auth="device", states=JOBS_STATES),

    # Admin endpoints
    "assets.generate_pairing_token_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "assets.revoke_pairing_token_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.approve_hardware_change_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.approve_recovery_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.create_device_job_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.get_device_jobs_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER}),
    "devices.pair_device_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.replace_endpoint_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.get_telemetry_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER}),
    "devices.verify_device_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.create_os_enrollment_token_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN}),
    "devices.get_recovery_requests_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER}),
    "devices.get_unclaimed_devices_endpoint": Policy(auth="role", roles={UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER}),
}


def _execute_device_pipeline(f: Any, policy: Policy, *args: Any, **kwargs: Any) -> Any:
    """Execute standard 7-step cryptographic verification and policy pipeline."""
    # 1. Validate required headers and body size
    device_id = request.headers.get("X-Device-ID")
    timestamp_str = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    key_version_str = request.headers.get("X-Key-Version")
    sig_b64 = request.headers.get("X-Signature")

    if not all([device_id, timestamp_str, nonce, key_version_str, sig_b64]):
        logger.warning("Rejecting request to %s: missing headers", request.path)
        return jsonify({"error": "unauthorized", "message": "Missing authentication headers"}), 401

    max_len = current_app.config.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)
    if request.content_length and request.content_length > max_len:
        logger.warning("Rejecting request from %s: payload exceeds %s bytes", device_id, max_len)
        return jsonify({"error": "unauthorized", "message": "Payload too large"}), 401

    # 2. Validate timestamp skew
    try:
        req_ts = int(timestamp_str)
    except (ValueError, TypeError):
        return jsonify({"error": "unauthorized", "message": "Invalid timestamp format"}), 401

    skew_limit = current_app.config.get("CLOCK_SKEW_SECONDS", 120)
    current_ts = int(time.time())
    if abs(current_ts - req_ts) > skew_limit:
        logger.warning("Rejecting request from %s: clock skew %s exceeds %s", device_id, abs(current_ts - req_ts), skew_limit)
        return jsonify({"error": "unauthorized", "message": "Timestamp out of allowable skew window"}), 401

    # 3. Load device and check key version
    device = PhysicalDevice.query.filter_by(device_id=device_id).first()
    if not device:
        logger.warning("Rejecting request: device %s not found", device_id)
        return jsonify({"error": "unauthorized", "message": "Device not found"}), 401

    try:
        key_version = int(key_version_str)
    except (ValueError, TypeError):
        return jsonify({"error": "unauthorized", "message": "Invalid key version format"}), 401

    from app.models.device import DeviceCredential
    active_creds = DeviceCredential.query.filter_by(
        device_id=device.id,
        status="ACTIVE",
    ).all()

    valid_versions = {device.credential_version}
    if active_creds:
        valid_versions.update(c.credential_version for c in active_creds)

    if key_version not in valid_versions:
        logger.warning("Rejecting request from %s: key version %s not in %s", device_id, key_version, valid_versions)
        return jsonify({"error": "unauthorized", "message": "Key version mismatch"}), 401

    # 4. Verify Ed25519 signature
    raw_body = request.get_data()
    path_with_query = request.full_path if request.query_string else request.path
    path_with_query = path_with_query.removesuffix("?")

    msg = canonical_string(request.method, path_with_query, timestamp_str, nonce, raw_body)
    verified = False
    if active_creds:
        for cred in active_creds:
            if cred.credential_version == key_version and verify(cred.public_key, sig_b64, msg):
                verified = True
                break

    if not verified and key_version == device.credential_version and verify(device.device_public_key, sig_b64, msg):
        verified = True

    if not verified:
        logger.warning("Rejecting request from %s: signature verification failed", device_id)
        return jsonify({"error": "unauthorized", "message": "Cryptographic signature verification failed"}), 401

    # 5. Atomically consume nonce
    if not check_and_record_nonce(device.device_id, nonce, skew_seconds=skew_limit):
        logger.warning("Rejecting request from %s: nonce %s replayed", device_id, nonce)
        return jsonify({"error": "unauthorized", "message": "Nonce replayed"}), 401

    # 6. Apply state policy
    if policy.states and device.status not in policy.states:
        logger.warning("Rejecting request from %s: status %s not allowed for %s", device_id, device.status.value, request.endpoint)
        return jsonify({"error": "device_blocked", "message": "Device is blocked"}), 403

    # 7. Execute operation
    g.current_device = device
    return f(*args, **kwargs)


def enforce_policy(f: Any) -> Any:
    """Decorator requiring request to comply with the endpoint's registered policy."""
    @functools.wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        endpoint = request.endpoint
        policy = ENDPOINT_POLICY.get(endpoint) or getattr(f, "_policy", None)
        if not policy:
            logger.warning("Unregistered endpoint %s accessed; failing closed", endpoint)
            return jsonify({"error": "unauthorized", "message": "No authorization policy registered"}), 401

        if policy.auth == "device":
            return _execute_device_pipeline(f, policy, *args, **kwargs)

        if policy.auth == "device_or_query":
            if request.headers.get("X-Signature"):
                return _execute_device_pipeline(f, policy, *args, **kwargs)
            return f(*args, **kwargs)

        if policy.auth == "role":
            from app.security.rbac import _authenticate_request

            user = _authenticate_request()
            if not user:
                return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

            if policy.roles and user.role not in policy.roles:
                return jsonify({"error": "forbidden", "message": f"Requires role: {[r.value for r in policy.roles]}"}), 403

            g.current_user = user
            return f(*args, **kwargs)

        return f(*args, **kwargs)

    return decorated
