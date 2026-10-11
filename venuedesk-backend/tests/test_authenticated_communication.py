"""Integration and unit tests for authenticated communication, heartbeats, and credential rotation."""
import base64
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.extensions import db
from app.models import (
    DeviceEvent,
    DeviceEventType,
    DeviceStatus,
    EventSeverity,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    generate_device_id,
)
from app.services.device_service import mark_offline_devices


def create_enrolled_device(
    app,
    status=DeviceStatus.ACTIVE,
    credential_version=1,
    last_seen=None,
    agent_instance_id="inst-1",
) -> tuple[str, Ed25519PrivateKey]:
    """Helper creating a PhysicalDevice and an active OSInstallation in DB."""
    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    dev_id = generate_device_id()
    now = datetime.now(UTC)

    with app.app_context():
        device = PhysicalDevice(
            device_id=dev_id,
            device_public_key=pub_b64,
            credential_version=credential_version,
            status=status,
            first_seen=now,
            last_seen=last_seen or now,
        )
        db.session.add(device)
        db.session.flush()

        os_inst = OSInstallation(
            device_id=device.id,
            os_family=OsFamily.LINUX,
            os_name="Ubuntu",
            os_version="24.04",
            architecture="x86_64",
            os_machine_id_hash="mid-hash-1",
            agent_instance_id=agent_instance_id,
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)
        db.session.commit()

    return dev_id, key


def sign_request(
    dev_id: str,
    key: Ed25519PrivateKey,
    method: str,
    path: str,
    body: bytes,
    key_version: int = 1,
    skew_seconds: int = 0,
    override_nonce: str | None = None,
) -> dict[str, str]:
    """Helper generating request authentication headers."""
    ts = str(int(time.time()) + skew_seconds)
    nonce = override_nonce or uuid.uuid4().hex
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{body_hash}".encode()
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")

    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": str(key_version),
        "X-Signature": sig,
    }


def test_signed_heartbeat_accepted_and_recovers_offline(client, app):
    """Test valid heartbeat is accepted and updates last_seen; transitions OFFLINE to ACTIVE."""
    dev_id, key = create_enrolled_device(
        app,
        status=DeviceStatus.OFFLINE,
        last_seen=datetime.now(UTC) - timedelta(minutes=5),
    )

    payload = {
        "device_id": dev_id,
        "timestamp": int(time.time()),
        "agent_version": "0.1.0",
        "agent_instance_id": "inst-1",
        "status": "ACTIVE",
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    headers["Content-Type"] = "application/json"

    res = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "server_time" in data
    assert data["config_version"] == 1
    assert not data["pending_jobs"]

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert device.status == DeviceStatus.ACTIVE
        # last_seen should be very recent (within 5 seconds)
        now = datetime.now(UTC)
        ls = device.last_seen if device.last_seen.tzinfo else device.last_seen.replace(tzinfo=UTC)
        assert (now - ls).total_seconds() < 5


def test_unsigned_or_tampered_request_rejected(client, app):
    dev_id, key = create_enrolled_device(app)

    # 1. Missing all headers -> 401
    r_no_headers = client.post("/api/v1/agents/heartbeat", json={})
    assert r_no_headers.status_code == 401

    # 2. Tampered body -> 401
    body_original = b'{"msg":"original"}'
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body_original)
    headers["Content-Type"] = "application/json"
    body_tampered = b'{"msg":"tampered"}'
    r_tampered = client.post("/api/v1/agents/heartbeat", data=body_tampered, headers=headers)
    assert r_tampered.status_code == 401

    # 3. Clock skew outside window -> 401
    headers_skew = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", b"", skew_seconds=300)
    r_skew = client.post("/api/v1/agents/heartbeat", data=b"", headers=headers_skew)
    assert r_skew.status_code == 401

    # 4. Key version mismatch -> 401
    headers_ver = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", b"", key_version=99)
    r_ver = client.post("/api/v1/agents/heartbeat", data=b"", headers=headers_ver)
    assert r_ver.status_code == 401


def test_replay_nonce_rejected(client, app):
    dev_id, key = create_enrolled_device(app)
    fixed_nonce = uuid.uuid4().hex
    body = b'{"ping":true}'

    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body, override_nonce=fixed_nonce)
    headers["Content-Type"] = "application/json"

    r1 = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert r1.status_code == 200

    # Replay same nonce -> 401
    r2 = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert r2.status_code == 401
    assert "nonce_replayed" in r2.get_json()["error"]


def test_revoked_device_blocked(client, app):
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.REVOKED)
    body = b"{}"
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    r = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert r.status_code == 403
    assert "device_blocked" in r.get_json()["error"]


def test_duplicate_device_detection(client, app):
    """Spec §4.9: Unexpected instance_id arriving within duplicate window triggers CRITICAL suspension."""
    dev_id, key = create_enrolled_device(app, last_seen=datetime.now(UTC), agent_instance_id="inst-registered")

    # Heartbeat from a different instance ID
    payload = {
        "device_id": dev_id,
        "timestamp": int(time.time()),
        "agent_instance_id": "inst-CLONE-SUSPICIOUS",
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    headers["Content-Type"] = "application/json"

    res = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert res.status_code == 403
    assert res.get_json()["error"] == "device_suspended"

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert device.status == DeviceStatus.SUSPENDED

        event = DeviceEvent.query.filter_by(
            device_id=device.id, event_type=DeviceEventType.DUPLICATE_DEVICE_IDENTITY
        ).first()
        assert event is not None
        assert event.severity == EventSeverity.CRITICAL


def test_credential_rotation(client, app):
    """Test public key rotation signed by old key; verifies old key is rejected and new key works."""
    dev_id, old_key = create_enrolled_device(app, credential_version=1)

    new_key = Ed25519PrivateKey.generate()
    new_pub_raw = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b64 = base64.b64encode(new_pub_raw).decode("ascii")

    ts = int(time.time())
    rot_msg = f"rotate\n{dev_id}\n{new_pub_b64}\n{ts}".encode()
    old_sig = base64.b64encode(old_key.sign(rot_msg)).decode("ascii")

    rot_payload = {
        "new_public_key": new_pub_b64,
        "signature_by_old_key": old_sig,
        "timestamp": ts,
    }
    body = json.dumps(rot_payload, separators=(",", ":")).encode("utf-8")
    headers = sign_request(dev_id, old_key, "POST", "/api/v1/agents/rotate-credential", body, key_version=1)
    headers["Content-Type"] = "application/json"

    r_rot = client.post("/api/v1/agents/rotate-credential", data=body, headers=headers)
    assert r_rot.status_code == 200
    assert r_rot.get_json()["credential_version"] == 2

    # Verification: Old key should now be rejected (version mismatch or invalid signature)
    hb_body = b'{"status":"ACTIVE"}'
    old_headers = sign_request(dev_id, old_key, "POST", "/api/v1/agents/heartbeat", hb_body, key_version=1)
    r_old = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=old_headers)
    assert r_old.status_code == 401

    # New key with version 2 should succeed
    new_headers = sign_request(dev_id, new_key, "POST", "/api/v1/agents/heartbeat", hb_body, key_version=2)
    r_new = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=new_headers)
    assert r_new.status_code == 200


def test_mark_offline_devices(app):
    """Test background offline marking job for stale active devices."""
    with app.app_context():
        # Fresh device (10 seconds ago)
        dev_fresh, _ = create_enrolled_device(app, last_seen=datetime.now(UTC) - timedelta(seconds=10))
        # Stale device (300 seconds ago, > 3*60s threshold)
        dev_stale, _ = create_enrolled_device(app, last_seen=datetime.now(UTC) - timedelta(seconds=300))

        marked = mark_offline_devices(heartbeat_interval_seconds=60)
        assert dev_stale in marked
        assert dev_fresh not in marked

        stale_obj = PhysicalDevice.query.filter_by(device_id=dev_stale).first()
        assert stale_obj.status == DeviceStatus.OFFLINE

        event = DeviceEvent.query.filter_by(
            device_id=stale_obj.id, event_type=DeviceEventType.HEARTBEAT_MISSED
        ).first()
        assert event is not None


def test_config_endpoint(client, app):
    """Test GET /api/v1/agents/config requires device auth and returns intervals."""
    dev_id, key = create_enrolled_device(app)
    headers = sign_request(dev_id, key, "GET", "/api/v1/agents/config", b"")

    res = client.get("/api/v1/agents/config", headers=headers)
    assert res.status_code == 200
    cfg = res.get_json()
    assert cfg["heartbeat_seconds"] == 60
    assert cfg["telemetry_seconds"] == 60
    assert cfg["config_version"] == 1
