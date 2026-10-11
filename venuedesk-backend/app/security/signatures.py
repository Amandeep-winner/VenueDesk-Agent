"""Ed25519 request signature verification and require_device_auth decorator."""
import base64
import functools
import hashlib
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import current_app, g, jsonify, request

from app.models import DeviceStatus, PhysicalDevice
from app.security.replay import check_and_record_nonce


def canonical_string(method: str, path_with_query: str, ts: str, nonce: str, body: bytes) -> bytes:
    """Construct deterministic canonical message for Ed25519 signature."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path_with_query}\n{ts}\n{nonce}\n{body_hash}".encode()


def verify(pub_b64: str, sig_b64: str, msg: bytes) -> bool:
    """Verify raw Ed25519 signature against base64 public key."""
    try:
        pub_bytes = base64.b64decode(pub_b64)
        sig_bytes = base64.b64decode(sig_b64)
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def require_device_auth(f):
    """Decorator requiring valid Ed25519 request signature from an authorized device."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        device_id = request.headers.get("X-Device-ID")
        timestamp_str = request.headers.get("X-Timestamp")
        nonce = request.headers.get("X-Nonce")
        key_version_str = request.headers.get("X-Key-Version")
        sig_b64 = request.headers.get("X-Signature")

        if not all([device_id, timestamp_str, nonce, key_version_str, sig_b64]):
            return jsonify({"error": "unauthorized", "message": "Missing authentication headers"}), 401

        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        if not device:
            return jsonify({"error": "unauthorized", "message": "Device not found"}), 401

        # 1. Device status check
        blocked_statuses = (DeviceStatus.REVOKED, DeviceStatus.SUSPENDED, DeviceStatus.RETIRED)
        if device.status in blocked_statuses:
            return jsonify({"error": "device_blocked", "message": f"Device is {device.status.value}"}), 403

        # 2. Key version match
        try:
            key_version = int(key_version_str)
        except ValueError:
            return jsonify({"error": "key_version_mismatch", "message": "Invalid key version format"}), 401

        if key_version != device.credential_version:
            return jsonify({"error": "key_version_mismatch", "message": "Credential version mismatch"}), 401

        # 3. Clock skew check
        try:
            req_ts = int(timestamp_str)
        except ValueError:
            return jsonify({"error": "clock_skew", "message": "Invalid timestamp format"}), 401

        skew_limit = current_app.config.get("CLOCK_SKEW_SECONDS", 120)
        current_ts = int(time.time())
        if abs(current_ts - req_ts) > skew_limit:
            return jsonify({"error": "clock_skew", "message": "Timestamp out of allowable skew window"}), 401

        # 4. Nonce replay check
        if not check_and_record_nonce(device_id, nonce, skew_seconds=skew_limit):
            return jsonify({"error": "nonce_replayed", "message": "Nonce already used or replayed"}), 401

        # 5. Signature verification
        raw_body = request.get_data()
        path_with_query = request.full_path.rstrip("?") if request.query_string else request.path
        canonical = canonical_string(request.method, path_with_query, timestamp_str, nonce, raw_body)

        if not verify(device.device_public_key, sig_b64, canonical):
            return jsonify({"error": "invalid_signature", "message": "Signature verification failed"}), 401

        g.current_device = device
        return f(*args, **kwargs)

    return decorated
