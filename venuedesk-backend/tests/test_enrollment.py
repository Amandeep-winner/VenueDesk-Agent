"""Integration and unit tests for agent enrollment and pairing token lifecycle."""

import base64
import hashlib
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.api.agents import reset_rate_limits
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EnrollmentToken,
    EnrollmentTokenStatus,
    OSInstallation,
    PhysicalDevice,
    RelationshipStatus,
    User,
    UserRole,
    generate_next_asset_id,
)
from app.security.tokens import create_token_for_asset


def create_test_endpoint_payload(
    token: str | None = None,
    skew_seconds: int = 0,
    bad_signature: bool = False,
    override_nonce: str | None = None,
    hardware_suffix: str = "1",
) -> tuple[dict, Ed25519PrivateKey]:
    """Helper creating a cryptographically valid enrollment payload."""
    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")

    token_sha256 = hashlib.sha256(token.strip().encode("utf-8")).hexdigest() if token else ""
    ts = int(time.time()) + skew_seconds
    nonce = override_nonce or uuid.uuid4().hex

    proof_message = f"enroll\n{token_sha256}\n{ts}\n{nonce}".encode()
    if bad_signature:
        bad_key = Ed25519PrivateKey.generate()
        sig = base64.b64encode(bad_key.sign(proof_message)).decode("ascii")
    else:
        sig = base64.b64encode(key.sign(proof_message)).decode("ascii")

    payload = {
        "enrollment_token": token,
        "device_public_key": pub_b64,
        "proof_of_possession": sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": f"uuid-hash-{hardware_suffix}",
            "bios_serial_hash": f"bios-hash-{hardware_suffix}",
            "motherboard_serial_hash": "mobo-shared-model",
            "cpu_signature": "intel core i7",
            "gpu_signature": "nvidia rtx 3070",
            "disk_identity_hash": f"disk-hash-{hardware_suffix}",
            "network_identity_hash": f"net-hash-{hardware_suffix}",
            "tpm_identity": None,
            "fingerprint": f"fp-hash-{hardware_suffix}",
            "fingerprint_version": 1,
        },
        "inventory": {
            "hostname": f"lab-pc-{hardware_suffix}",
            "ip_addresses": [f"192.168.1.{hardware_suffix}"],
            "mac_addresses": [f"00:11:22:33:44:{hardware_suffix}"],
            "cpu_model": "Intel Core i7",
            "cpu_cores": 8,
            "ram_total_mb": 16384,
            "gpus": ["NVIDIA RTX 3070"],
            "disks": ["Samsung SSD 970"],
            "os_summary": "Ubuntu 24.04",
            "agent_version": "0.1.0",
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": f"os-hash-{hardware_suffix}",
        },
        "agent_version": "0.1.0",
        "agent_instance_id": f"inst-{hardware_suffix}",
    }
    return payload, key


@pytest.fixture(autouse=True)
def clean_rate_limits():
    reset_rate_limits()


def test_enrollment_happy_path(client, app):
    """Test standard enrollment with valid pairing token."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(),
            asset_tag="TAG-LAB-01",
            lifecycle_status=AssetLifecycleStatus.DRAFT,
        )
        db.session.add(asset)
        db.session.flush()

        raw_token, token_row = create_token_for_asset(asset.id, created_by="admin")
        token_hash = token_row.token_hash
        db.session.commit()
        asset_id = asset.asset_id

    payload, _ = create_test_endpoint_payload(token=raw_token)

    res = client.post("/api/v1/agents/enroll", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == DeviceStatus.PENDING_VERIFICATION.value
    assert data["asset_id"] == asset_id
    assert data["device_id"].startswith("VD-DEVICE-")
    assert data["credential"]["credential_version"] == 1

    with app.app_context():
        # Verify PhysicalDevice
        device = PhysicalDevice.query.filter_by(device_id=data["device_id"]).first()
        assert device is not None
        assert device.status == DeviceStatus.PENDING_VERIFICATION

        # Verify Link
        link = AssetDeviceLink.query.filter_by(device_id=device.id).first()
        assert link is not None
        assert link.relationship_status == RelationshipStatus.ACTIVE
        assert link.asset.asset_id == asset_id

        # Verify Asset status
        asset_db = Asset.query.filter_by(asset_id=asset_id).first()
        assert asset_db.lifecycle_status == AssetLifecycleStatus.PENDING_VERIFICATION

        # Verify Token marked USED
        tok_db = EnrollmentToken.query.filter_by(token_hash=token_hash).first()
        assert tok_db.status == EnrollmentTokenStatus.USED
        assert tok_db.used_by_device_id == device.id

        # Verify Evidence snapshot
        ev_db = DeviceIdentityEvidence.query.filter_by(device_id=device.id).first()
        assert ev_db is not None
        assert not ev_db.trusted

        # Verify OS Installation
        os_db = OSInstallation.query.filter_by(device_id=device.id).first()
        assert os_db is not None
        assert os_db.agent_instance_id == "inst-1"

        # Verify Inventory
        inv_db = DeviceInventory.query.filter_by(device_id=device.id).first()
        assert inv_db is not None
        assert inv_db.hostname == "lab-pc-1"

        # Verify Audit logs
        audit_dev = AuditLog.query.filter_by(
            action=AuditAction.DEVICE_ENROLLED, entity_id=device.device_id
        ).first()
        assert audit_dev is not None
        audit_link = AuditLog.query.filter_by(action=AuditAction.DEVICE_LINKED).first()
        assert audit_link is not None


def test_enrollment_token_single_use(client, app):
    """Enrolling a second time with same token must fail."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id())
        db.session.add(asset)
        db.session.flush()
        raw_token, _ = create_token_for_asset(asset.id)
        db.session.commit()

    payload1, _ = create_test_endpoint_payload(token=raw_token, hardware_suffix="1")
    payload2, _ = create_test_endpoint_payload(token=raw_token, hardware_suffix="2")

    res1 = client.post("/api/v1/agents/enroll", json=payload1)
    assert res1.status_code == 200

    res2 = client.post("/api/v1/agents/enroll", json=payload2)
    assert res2.status_code == 400
    assert "not active" in res2.get_json()["message"]


def test_enrollment_expired_or_revoked_token(client, app):
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id())
        db.session.add(asset)
        db.session.flush()

        raw_token1, tok1 = create_token_for_asset(asset.id)
        # Manually expire tok1
        tok1.expires_at = datetime.now(UTC) - timedelta(hours=1)

        raw_token2, tok2 = create_token_for_asset(asset.id)  # Revokes tok1 and creates tok2
        tok2.status = EnrollmentTokenStatus.REVOKED

        db.session.commit()

    # Expired token
    p1, _ = create_test_endpoint_payload(token=raw_token1)
    r1 = client.post("/api/v1/agents/enroll", json=p1)
    assert r1.status_code == 400

    # Revoked token
    p2, _ = create_test_endpoint_payload(token=raw_token2)
    r2 = client.post("/api/v1/agents/enroll", json=p2)
    assert r2.status_code == 400
    assert "not active" in r2.get_json()["message"]


def test_enrollment_proof_of_possession_mismatch(client, app):
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id())
        db.session.add(asset)
        db.session.flush()
        raw_token, _ = create_token_for_asset(asset.id)
        db.session.commit()

    payload, _ = create_test_endpoint_payload(token=raw_token, bad_signature=True)
    res = client.post("/api/v1/agents/enroll", json=payload)
    assert res.status_code == 400
    assert "proof of possession" in res.get_json()["message"].lower()


def test_two_near_identical_endpoints_map_to_different_assets(client, app):
    """Acceptance test 6: Two endpoints with identical hardware specs map to different Assets via tokens."""
    with app.app_context():
        asset_a = Asset(asset_id=generate_next_asset_id(), asset_tag="PC-ALPHA")
        asset_b = Asset(asset_id=generate_next_asset_id(), asset_tag="PC-BETA")
        db.session.add_all([asset_a, asset_b])
        db.session.flush()

        raw_tok_a, _ = create_token_for_asset(asset_a.id)
        raw_tok_b, _ = create_token_for_asset(asset_b.id)
        db.session.commit()

        id_a, id_b = asset_a.asset_id, asset_b.asset_id

    # Identical hardware specs across both payloads
    payload_a, _ = create_test_endpoint_payload(token=raw_tok_a, hardware_suffix="shared-hw-a")
    payload_b, _ = create_test_endpoint_payload(token=raw_tok_b, hardware_suffix="shared-hw-b")

    res_a = client.post("/api/v1/agents/enroll", json=payload_a)
    assert res_a.status_code == 200
    dev_a = res_a.get_json()

    res_b = client.post("/api/v1/agents/enroll", json=payload_b)
    assert res_b.status_code == 200
    dev_b = res_b.get_json()

    # Mappings are strictly determined by token authority, not hardware similarity
    assert dev_a["asset_id"] == id_a
    assert dev_b["asset_id"] == id_b
    assert dev_a["device_id"] != dev_b["device_id"]


def test_unclaimed_enrollment_mode(client, app):
    """Test unclaimed mode off by default and enabled conditionally."""
    payload, _ = create_test_endpoint_payload(token=None)

    # Off by default in test config -> 403
    res_off = client.post("/api/v1/agents/enroll", json=payload)
    assert res_off.status_code == 403
    assert res_off.get_json()["error"] == "unclaimed_enrollment_disabled"

    # Enable flag
    app.config["ALLOW_UNCLAIMED_ENROLLMENT"] = True
    try:
        payload_on, _ = create_test_endpoint_payload(token=None, hardware_suffix="unclaimed-ok")
        res_on = client.post("/api/v1/agents/enroll", json=payload_on)
        assert res_on.status_code == 200
        data = res_on.get_json()
        assert data["status"] == DeviceStatus.UNCLAIMED.value
        assert data["asset_id"] is None

        with app.app_context():
            dev = PhysicalDevice.query.filter_by(device_id=data["device_id"]).first()
            assert dev.status == DeviceStatus.UNCLAIMED
            # No link created
            assert len(dev.links) == 0
            # Event emitted
            event = DeviceEvent.query.filter_by(
                device_id=dev.id, event_type=DeviceEventType.UNCLAIMED_DEVICE_DISCOVERED
            ).first()
            assert event is not None
    finally:
        app.config["ALLOW_UNCLAIMED_ENROLLMENT"] = False


def test_enrollment_rate_limiting(client, app):
    """Test rate limiting rejects >10 attempts in window."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id())
        db.session.add(asset)
        db.session.commit()

    # Fire 10 invalid requests
    for i in range(10):
        p, _ = create_test_endpoint_payload(token="PAIR-invalid-token", hardware_suffix=str(i))
        r = client.post("/api/v1/agents/enroll", json=p)
        assert r.status_code == 400

    # 11th request should be rate limited (429)
    p_last, _ = create_test_endpoint_payload(token="PAIR-invalid-token", hardware_suffix="11")
    r_limit = client.post("/api/v1/agents/enroll", json=p_last)
    assert r_limit.status_code == 429
    assert r_limit.get_json()["error"] == "rate_limited"


def test_admin_pairing_token_endpoints(client, app):
    """Test admin create and delete pairing-token endpoints."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(), asset_tag="ADMIN-ASSET")
        admin = User(username="adminuser", role=UserRole.INFRA_ADMIN)
        admin.set_password("SecurePass123!")
        db.session.add_all([asset, admin])
        db.session.commit()
        aid = asset.asset_id

    # Unauthorized access rejected
    r_unauth = client.post(f"/api/v1/admin/assets/{aid}/pairing-token")
    assert r_unauth.status_code == 401

    headers = {"Authorization": "Basic " + base64.b64encode(b"adminuser:SecurePass123!").decode()}

    # Create pairing token
    r_create = client.post(f"/api/v1/admin/assets/{aid}/pairing-token", headers=headers)
    assert r_create.status_code == 201
    tok_data = r_create.get_json()
    assert tok_data["token"].startswith("PAIR-")
    assert tok_data["asset_id"] == aid

    # Delete (revoke) pairing token
    r_delete = client.delete(f"/api/v1/admin/assets/{aid}/pairing-token", headers=headers)
    assert r_delete.status_code == 200
    assert r_delete.get_json()["status"] == "revoked"

    # Enrolling with revoked token fails
    p, _ = create_test_endpoint_payload(token=tok_data["token"])
    r_enroll = client.post("/api/v1/agents/enroll", json=p)
    assert r_enroll.status_code == 400
