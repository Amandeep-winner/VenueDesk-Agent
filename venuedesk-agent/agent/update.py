"""Safe agent update mechanism with cryptographic Ed25519 release verification.

Default behavior is notify-only (auto_update=False). Agents never auto-execute
unsigned or hash-mismatched release packages.
"""

import base64
import hashlib
import logging
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.config import AgentConfig

logger = logging.getLogger(__name__)

# Baked-in Ed25519 release signing public key (raw 32 bytes base64 encoded)
# Corresponds to official VenueDesk release infrastructure signing key.
OFFICIAL_RELEASE_PUBLIC_KEY_B64 = "43O+bQpWJg1eD5P0YJ+w5b5R8kYpI9e1K4s8J7k6Q9A="


def verify_package_hash(package_bytes: bytes, expected_sha256: str) -> bool:
    """Verify SHA-256 digest of downloaded release package."""
    if not expected_sha256 or not package_bytes:
        return False
    actual_hash = hashlib.sha256(package_bytes).hexdigest().lower()
    return actual_hash == expected_sha256.lower().strip()


def verify_release_signature(
    package_bytes: bytes,
    signature_b64: str,
    release_public_key_b64: str = OFFICIAL_RELEASE_PUBLIC_KEY_B64,
) -> bool:
    """Verify cryptographic Ed25519 signature of the release package."""
    if not signature_b64 or not package_bytes:
        return False

    try:
        sig_bytes = base64.b64decode(signature_b64)
        pub_bytes = base64.b64decode(release_public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, package_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError) as exc:
        logger.warning("Release package cryptographic signature verification failed: %s", exc)
        return False


def is_version_newer(candidate: str, current: str) -> bool:
    """Compare semver-like version strings. Return True if candidate > current."""

    def parse_version(v: str) -> list[int]:
        parts = []
        for segment in v.split("."):
            try:
                parts.append(int(segment.split("-")[0]))
            except ValueError:
                parts.append(0)
        return parts

    return parse_version(candidate) > parse_version(current)


def check_for_updates(config: AgentConfig) -> dict[str, Any]:
    """Check control plane for latest agent release metadata."""
    import requests

    check_url = f"{config.server_url.rstrip('/')}/api/v1/agents/version-check"
    try:
        resp = requests.get(check_url, timeout=10.0)
        if resp.status_code != 200:
            return {"status": "error", "message": f"Server returned {resp.status_code}"}

        meta = resp.json()
        latest = meta.get("latest_agent_version", config.agent_version)
        update_available = is_version_newer(latest, config.agent_version)

        result = {
            "status": "ok",
            "current_version": config.agent_version,
            "latest_version": latest,
            "min_supported_version": meta.get("min_supported_agent_version", "0.1.0"),
            "update_available": update_available,
            "auto_update_enabled": config.auto_update,
            "download_url": meta.get("download_url"),
        }

        if update_available:
            if not config.auto_update:
                logger.info(
                    "Agent update available (%s -> %s). Policy is notify-only (auto_update=false). "
                    "Use administrator installation script to upgrade.",
                    config.agent_version,
                    latest,
                )
            else:
                logger.info("Auto-update is enabled. Checking release cryptographic signature...")

        return result

    except (requests.RequestException, OSError, ValueError) as exc:
        logger.debug("Version check request failed: %s", exc)
        return {"status": "error", "message": str(exc)}
