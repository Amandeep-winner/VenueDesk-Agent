"""Agent request signing and header construction for device authentication."""
import hashlib
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.identity.keys import sign_message


def build_canonical_string(
    method: str,
    path_with_query: str,
    timestamp: int | str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Construct deterministic canonical message for Ed25519 signing matching backend specification."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path_with_query}\n{timestamp}\n{nonce}\n{body_hash}".encode()


def generate_auth_headers(
    device_id: str,
    private_key: Ed25519PrivateKey,
    credential_version: int,
    method: str,
    path_with_query: str,
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Generate authenticated request headers (X-Device-ID, X-Timestamp, X-Nonce, X-Key-Version, X-Signature)."""
    ts = str(timestamp if timestamp is not None else int(time.time()))
    req_nonce = nonce or uuid.uuid4().hex
    canonical = build_canonical_string(method, path_with_query, ts, req_nonce, body)
    signature_b64 = sign_message(private_key, canonical)

    return {
        "X-Device-ID": device_id,
        "X-Timestamp": ts,
        "X-Nonce": req_nonce,
        "X-Key-Version": str(credential_version),
        "X-Signature": signature_b64,
    }
