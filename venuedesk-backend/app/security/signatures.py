"""Ed25519 request signature verification and require_device_auth decorator."""
import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


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
    from app.models.device import DeviceStatus
    from app.security.policy import Policy, enforce_policy

    if not hasattr(f, "_policy"):
        f._policy = Policy(auth="device", states={DeviceStatus.ACTIVE})
    return enforce_policy(f)
