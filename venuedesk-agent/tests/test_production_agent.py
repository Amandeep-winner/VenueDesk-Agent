"""Tests for agent Phase 8 production hardening, URL security, and safe updates."""

import base64
import hashlib

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.config import AgentConfig
from agent.main import cli
from agent.update import (
    is_version_newer,
    verify_package_hash,
    verify_release_signature,
)


def test_agent_refuses_http_url_without_dev_flag():
    """Agent rejects unencrypted HTTP URLs in production unless allow_insecure_dev=True."""
    cfg_insecure = AgentConfig(server_url="http://control.venue.internal", allow_insecure_dev=False)
    with pytest.raises(ValueError, match="Insecure HTTP server URLs are rejected"):
        cfg_insecure.validate_server_url()

    # Allowed with explicit dev bypass
    cfg = AgentConfig(server_url="http://127.0.0.1:5001", allow_insecure_dev=True)
    assert cfg.allow_insecure_dev is True

    # HTTPS is always allowed
    cfg_https = AgentConfig(server_url="https://control.venue.internal", allow_insecure_dev=False)
    assert cfg_https.server_url == "https://control.venue.internal"


def test_safe_update_package_hash_verification():
    """Verify package hash matching and tamper detection."""
    payload = b"venuedesk-agent-v0.2.0-distribution-package-bytes"
    expected_hash = hashlib.sha256(payload).hexdigest()

    assert verify_package_hash(payload, expected_hash) is True
    assert verify_package_hash(payload, "invalid_hash") is False
    assert verify_package_hash(b"tampered_bytes", expected_hash) is False


def test_safe_update_ed25519_signature_verification():
    """Verify Ed25519 release signature verification passes for valid signatures and rejects tampered."""
    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()
    pub_b64 = base64.b64encode(pub_key.public_bytes_raw()).decode("utf-8")

    package_data = b"venuedesk-agent-release-package-0.2.0"
    signature = private_key.sign(package_data)
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    assert verify_release_signature(package_data, sig_b64, release_public_key_b64=pub_b64) is True
    # Tampered data fails
    assert (
        verify_release_signature(b"tampered_data", sig_b64, release_public_key_b64=pub_b64) is False
    )
    # Bad signature fails
    assert (
        verify_release_signature(package_data, "bad_sig", release_public_key_b64=pub_b64) is False
    )


def test_version_comparison():
    """Verify semver version comparisons."""
    assert is_version_newer("0.2.0", "0.1.0") is True
    assert is_version_newer("1.0.0", "0.9.9") is True
    assert is_version_newer("0.1.0", "0.1.0") is False
    assert is_version_newer("0.0.9", "0.1.0") is False


def test_agent_status_cli_command(tmp_path):
    """Verify venuedesk-agent status prints structured health output."""
    runner = CliRunner()
    state_dir = tmp_path / "agent_state"
    state_dir.mkdir()

    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f"""
server_url = "https://127.0.0.1:5001"
state_dir = "{state_dir.as_posix()}"
allow_insecure_dev = true
""")

    result = runner.invoke(cli, ["--config", str(cfg_file), "status"])
    assert result.exit_code == 0
    assert "VenueDesk Agent Health Status" in result.output
    assert "Agent Version:" in result.output
    assert "Enrolled:" in result.output
    assert "Queue Depth:" in result.output
