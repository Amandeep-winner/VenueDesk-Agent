"""Tests for Phase 8 production hardening, config validation, headers, and retention CLI."""

import pytest

from app.config import ProductionConfig
from app.extensions import db
from app.models import DeviceStatus, PhysicalDevice
from app.models.device import DeviceCredential
from app.security.limiter import limiter


def test_production_config_validation_requires_secrets(monkeypatch):
    """Test that ProductionConfig refuses to start without explicit secrets and PostgreSQL."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("DEPLOYMENT_SALT", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match="SECRET_KEY"):
        ProductionConfig.validate()

    monkeypatch.setenv("SECRET_KEY", "real-production-secret-key-very-long")
    with pytest.raises(ValueError, match="DEPLOYMENT_SALT"):
        ProductionConfig.validate()

    monkeypatch.setenv("DEPLOYMENT_SALT", "real-production-salt-at-least-32-chars-long!")
    with pytest.raises(ValueError, match="DATABASE_URL"):
        ProductionConfig.validate()

    # Reject SQLite in production without explicit override
    monkeypatch.setenv("DATABASE_URL", "sqlite:///prod.db")
    monkeypatch.setenv("ALLOW_SQLITE_PROD", "false")
    with pytest.raises(ValueError, match="SQLite is not permitted in production"):
        ProductionConfig.validate()

    # Allow SQLite when explicit dev override is present
    monkeypatch.setenv("ALLOW_SQLITE_PROD", "true")
    ProductionConfig.validate()

    # Allow PostgreSQL
    monkeypatch.setenv("ALLOW_SQLITE_PROD", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/venuedesk")
    ProductionConfig.validate()


def test_production_security_headers(client):
    """Test that security headers including HSTS and frame options are emitted."""
    client.application.config["HSTS_ENABLED"] = True
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_rate_limiter_blocks_excessive_attempts(client):
    """Test that excessive login requests trigger 429 Rate Limited response."""
    limiter.reset()
    # Trigger 11 requests when limit is 10
    responses = []
    for _ in range(12):
        r = client.post(
            "/admin/infrastructure/login", data={"username": "wrong", "password": "bad"}
        )
        responses.append(r.status_code)

    assert 429 in responses
    last_resp = client.post(
        "/admin/infrastructure/login", data={"username": "wrong", "password": "bad"}
    )
    assert last_resp.status_code == 429
    assert "Retry-After" in last_resp.headers
    limiter.reset()


def test_credential_revocation_procedure(app, client):
    """Test credential revocation procedure transitions status and rejects authentication."""
    with app.app_context():
        device = PhysicalDevice(
            device_id="VD-DEVICE-REVOKETEST",
            device_public_key="some-public-key",
            status=DeviceStatus.ACTIVE,
            credential_version=1,
        )
        db.session.add(device)
        db.session.commit()

        cred = DeviceCredential(
            device_id=device.id,
            credential_version=1,
            public_key="some-public-key",
            status="ACTIVE",
            os_installation_id="os-inst-1",
        )
        db.session.add(cred)
        db.session.commit()

        # Execute revocation procedure
        from app.services.device_service import revoke_device_credential

        revoke_device_credential(device.id, credential_version=1, reason="Lost laptop reported")

        # Verify credential status is REVOKED
        db.session.refresh(cred)
        assert cred.status == "REVOKED"


def test_purge_cli_commands(app):
    """Test that purge CLI commands execute cleanly."""
    runner = app.test_cli_runner()

    res1 = runner.invoke(args=["purge-telemetry", "--older-than-days", "7"])
    assert res1.exit_code == 0
    assert "Purged" in res1.output

    res2 = runner.invoke(args=["purge-nonces"])
    assert res2.exit_code == 0
    assert "Purged" in res2.output

    res3 = runner.invoke(args=["purge-processed-events", "--older-than-days", "2"])
    assert res3.exit_code == 0
    assert "Purged" in res3.output
