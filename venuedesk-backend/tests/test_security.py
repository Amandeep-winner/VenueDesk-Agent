"""Comprehensive unit tests for security primitives, signatures, tokens, and replay defense."""
import base64
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import jsonify

from app.extensions import db
from app.models import (
    Asset,
    DeviceStatus,
    EnrollmentToken,
    EnrollmentTokenStatus,
    PhysicalDevice,
    generate_device_id,
    generate_next_asset_id,
)
from app.security import (
    canonical_string,
    consume_token_atomically,
    create_token_for_asset,
    hash_token,
    require_device_auth,
)


@pytest.fixture
def test_device_keypair(app):
    """Generate Ed25519 keypair and register test PhysicalDevice."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    with app.app_context():
        device = PhysicalDevice(
            device_id=generate_device_id(),
            device_public_key=pub_b64,
            status=DeviceStatus.ACTIVE,
            credential_version=1
        )
        db.session.add(device)
        db.session.commit()
        dev_id = device.device_id

    return priv, pub_b64, dev_id


def test_token_hashing_never_stores_raw(app):
    """Verify raw token is never persisted in database."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-TOK-01")
        db.session.add(asset)
        db.session.commit()

        raw_tok, tok_obj = create_token_for_asset(asset.id)
        assert raw_tok.startswith("PAIR-")
        assert tok_obj.token_hash == hash_token(raw_tok)
        assert raw_tok not in tok_obj.token_hash

        retrieved = EnrollmentToken.query.filter_by(token_hash=hash_token(raw_tok)).first()
        assert retrieved is not None
        assert retrieved.status == EnrollmentTokenStatus.ACTIVE


def test_token_reuse_rejected(app):
    """Verify pairing token cannot be consumed twice."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-TOK-02")
        db.session.add(asset)
        db.session.commit()

        raw_tok, _ = create_token_for_asset(asset.id)

        # First consumption succeeds
        consumed = consume_token_atomically(raw_tok)
        assert consumed.status == EnrollmentTokenStatus.USED

        # Second consumption fails
        with pytest.raises(ValueError, match="is not active"):
            consume_token_atomically(raw_tok)


def test_token_expiry_rejected(app):
    """Verify expired token is rejected."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-TOK-03")
        db.session.add(asset)
        db.session.commit()

        raw_tok, tok_obj = create_token_for_asset(asset.id)
        # Manually expire
        tok_obj.expires_at = datetime.now(UTC) - timedelta(hours=1)
        db.session.commit()

        with pytest.raises(ValueError, match="expired"):
            consume_token_atomically(raw_tok)


def test_signature_verification_flow(app, client, test_device_keypair):
    """Test valid Ed25519 signature request through @require_device_auth."""
    priv, _pub_b64, dev_id = test_device_keypair

    # Register protected route on app
    @app.route("/test-secure", methods=["POST"])
    @require_device_auth
    def secure_endpoint():
        return jsonify({"status": "authenticated"}), 200

    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    body = b'{"msg":"hello"}'

    canon = canonical_string("POST", "/test-secure", ts, nonce, body)
    sig = base64.b64encode(priv.sign(canon)).decode("ascii")

    headers = {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": "1",
        "X-Signature": sig,
        "Content-Type": "application/json"
    }

    # 1. Valid request
    res = client.post("/test-secure", data=body, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["status"] == "authenticated"

    # 2. Tampered body fails
    tampered_body = b'{"msg":"tampered"}'
    res = client.post("/test-secure", data=tampered_body, headers=headers)
    assert res.status_code == 401

    # 3. Nonce replay fails (exact same nonce)
    res = client.post("/test-secure", data=body, headers=headers)
    assert res.status_code == 401


def test_clock_skew_rejected(app, client, test_device_keypair):
    """Verify request with expired timestamp is rejected."""
    priv, _pub_b64, dev_id = test_device_keypair

    @app.route("/test-skew", methods=["GET"])
    @require_device_auth
    def skew_endpoint():
        return jsonify({"status": "ok"}), 200

    # 5 minutes in the past
    past_ts = str(int(time.time()) - 300)
    nonce = uuid.uuid4().hex
    canon = canonical_string("GET", "/test-skew", past_ts, nonce, b"")
    sig = base64.b64encode(priv.sign(canon)).decode("ascii")

    headers = {
        "X-Device-ID": dev_id,
        "X-Timestamp": past_ts,
        "X-Nonce": nonce,
        "X-Key-Version": "1",
        "X-Signature": sig,
    }

    res = client.get("/test-skew", headers=headers)
    assert res.status_code == 401
    assert res.get_json()["error"] == "clock_skew"


def test_blocked_device_returns_403(app, client, test_device_keypair):
    """Verify REVOKED device is rejected with 403."""
    priv, _pub_b64, dev_id = test_device_keypair

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        device.status = DeviceStatus.REVOKED
        db.session.commit()

    @app.route("/test-blocked", methods=["GET"])
    @require_device_auth
    def blocked_endpoint():
        return jsonify({"status": "ok"}), 200

    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canon = canonical_string("GET", "/test-blocked", ts, nonce, b"")
    sig = base64.b64encode(priv.sign(canon)).decode("ascii")

    headers = {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": "1",
        "X-Signature": sig,
    }

    res = client.get("/test-blocked", headers=headers)
    assert res.status_code == 403
    assert res.get_json()["error"] == "device_blocked"
