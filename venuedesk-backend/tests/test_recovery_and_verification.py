"""Unit and integration tests for Phase 8: Recovery & Verification Workflows."""
import base64
import hashlib
import time
import uuid
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    AssetVerificationStatus,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EventSeverity,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    User,
    UserRole,
    Verification,
    VerificationMethod,
    generate_device_id,
    generate_next_asset_id,
)
from app.security.tokens import create_token_for_asset


def create_asset_and_device(app, hostname="ws-recover-01", mb_serial="MB-REC-111", uuid_str="UUID-REC-222"):
    """Helper to set up an institutional asset, physical device, active link, and trusted evidence."""
    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    dev_id = generate_device_id()
    now = datetime.now(UTC)

    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag=f"TAG-{dev_id[10:]}",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
            verification_status=AssetVerificationStatus.UNVERIFIED,
        )
        db.session.add(asset)
        db.session.flush()

        device = PhysicalDevice(
            device_id=dev_id,
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(device)
        db.session.flush()

        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=device.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_at=now,
            linked_by="system",
        )
        db.session.add(link)

        evidence = DeviceIdentityEvidence(
            device_id=device.id,
            machine_uuid_hash=uuid_str,
            motherboard_serial_hash=mb_serial,
            bios_serial_hash="BIOS-REC-333",
            cpu_signature="Intel i7-12700",
            disk_identity_hash="DISK-NVME-01",
            network_identity_hash="MAC-ETH-01",
            tpm_identity="TPM-CHIP-01",
            fingerprint="fp-initial-rec",
            captured_at=now,
            trusted=True,
        )
        db.session.add(evidence)

        inv = DeviceInventory(
            device_id=device.id,
            hostname=hostname,
            ip_addresses=["10.10.10.20"],
            mac_addresses=["00:aa:bb:cc:dd:ee"],
            cpu_model="Intel i7-12700",
            cpu_cores=12,
            ram_total_mb=16384,
            gpus=["NVIDIA RTX 3060"],
            disks=["Samsung 980 1TB"],
            os_summary="Ubuntu 22.04",
            bios_version="v2.1",
            tpm_present=True,
            agent_version="0.1.0",
            updated_at=now,
        )
        db.session.add(inv)

        os_inst = OSInstallation(
            device_id=device.id,
            os_family=OsFamily.LINUX,
            os_name="Ubuntu",
            os_version="22.04",
            architecture="x86_64",
            os_machine_id_hash="mid-ubuntu-22",
            agent_instance_id="inst-prev-ubuntu",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)
        db.session.commit()

        a_id = asset.asset_id
        d_id = device.device_id

    return d_id, a_id, key


def ensure_admin(app):
    with app.app_context():
        admin = User.query.filter_by(username="phase8_admin").first()
        if not admin:
            admin = User(username="phase8_admin", role=UserRole.INFRA_ADMIN)
            admin.set_password("adminpass")
            db.session.add(admin)
            db.session.commit()
    return {"Authorization": "Basic " + base64.b64encode(b"phase8_admin:adminpass").decode("ascii")}


def sign_req(dev_id: str, key: Ed25519PrivateKey, method: str, path: str, body: bytes, key_ver: int = 1) -> dict[str, str]:
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    b_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{b_hash}".encode()
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": str(key_ver),
        "X-Signature": sig,
    }


def make_proof_of_possession(key: Ed25519PrivateKey, pub_b64: str, ts: int, nonce: str) -> str:
    msg = f"recover\n{pub_b64}\n{ts}\n{nonce}".encode()
    return base64.b64encode(key.sign(msg)).decode("ascii")


def test_os_reinstall_recovery_end_to_end(client, app):
    """End-to-end test of OS reinstall recovery, polling, and admin approval."""
    dev_id, asset_id, old_key = create_asset_and_device(app)
    admin_headers = ensure_admin(app)

    # 1. New key generated on reinstall
    new_key = Ed25519PrivateKey.generate()
    new_pub_raw = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b64 = base64.b64encode(new_pub_raw).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    pop_sig = make_proof_of_possession(new_key, new_pub_b64, ts, nonce)

    # Matching hardware evidence with reinstalled OS
    recover_payload = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": pop_sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-REC-222",
            "motherboard_serial_hash": "MB-REC-111",
            "bios_serial_hash": "BIOS-REC-333",
            "cpu_signature": "Intel i7-12700",
            "disk_identity_hash": "DISK-NVME-01",
            "network_identity_hash": "MAC-ETH-01",
            "fingerprint": "fp-new-os-reinstall",
        },
        "inventory": {
            "hostname": "ws-recover-01-new",
            "ip_addresses": ["10.10.10.25"],
            "mac_addresses": ["00:aa:bb:cc:dd:ee"],
            "cpu_model": "Intel i7-12700",
            "cpu_cores": 12,
            "ram_total_mb": 16384,
            "gpus": ["NVIDIA RTX 3060"],
            "disks": ["Samsung 980 1TB"],
            "os_summary": "Ubuntu 24.04 LTS",
            "bios_version": "v2.1",
            "tpm_present": True,
            "agent_version": "0.1.0",
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": "mid-ubuntu-24-fresh",
        },
        "agent_instance_id": "inst-new-ubuntu-24",
    }

    # 2. Agent submits /recover
    resp = client.post("/api/v1/agents/recover", json=recover_payload)
    assert resp.status_code == 200, resp.data
    data = resp.get_json()
    assert data["status"] == "pending_approval"
    assert data["device_id"] == dev_id
    rec_req_id = data["recovery_request_id"]

    # 3. Verify device state is now PENDING_REVERIFICATION
    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.PENDING_REVERIFICATION

        # Check OS reinstall event
        evt = DeviceEvent.query.filter_by(device_id=dev.id, event_type=DeviceEventType.OS_REINSTALL_DETECTED).first()
        assert evt is not None
        assert evt.severity == EventSeverity.HIGH

    # 4. Agent polls /recover/status -> should be pending
    poll_resp = client.get(f"/api/v1/agents/recover/status?device_id={dev_id}")
    assert poll_resp.status_code == 200
    assert poll_resp.get_json()["status"] == "pending"

    # 5. Admin lists recovery requests
    admin_list_resp = client.get("/api/v1/admin/devices/recovery-requests", headers=admin_headers)
    assert admin_list_resp.status_code == 200
    list_data = admin_list_resp.get_json()
    assert any(r["id"] == rec_req_id and r["device_id"] == dev_id for r in list_data["recovery_requests"])

    # 6. Admin approves recovery
    approve_resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/approve-recovery",
        headers=admin_headers,
    )
    assert approve_resp.status_code == 200
    app_data = approve_resp.get_json()
    assert app_data["status"] == "approved"
    assert app_data["credential_version"] == 2
    assert app_data["device_status"] == DeviceStatus.ACTIVE.value

    # 7. Agent polls /recover/status again -> should be approved
    poll_approved = client.get(f"/api/v1/agents/recover/status?device_id={dev_id}")
    assert poll_approved.status_code == 200
    poll_data = poll_approved.get_json()
    assert poll_data["status"] == "approved"
    assert poll_data["credential_version"] == 2

    # 8. Check database state: credentials rotated, OS installation updated
    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        assert dev.credential_version == 2
        assert dev.device_public_key == new_pub_b64

        # Old OS must be HISTORICAL
        old_os = OSInstallation.query.filter_by(device_id=dev.id, os_machine_id_hash="mid-ubuntu-22").first()
        assert old_os.status == OsInstallationStatus.HISTORICAL

        # New OS must be ACTIVE
        new_os = OSInstallation.query.filter_by(device_id=dev.id, os_machine_id_hash="mid-ubuntu-24-fresh").first()
        assert new_os is not None
        assert new_os.status == OsInstallationStatus.ACTIVE
        assert new_os.os_version == "24.04"

        # Asset link preserved to the same asset
        active_link = AssetDeviceLink.query.filter_by(device_id=dev.id, relationship_status=RelationshipStatus.ACTIVE).first()
        assert active_link is not None
        assert active_link.asset.asset_id == asset_id

        # Audit log logged
        audit = AuditLog.query.filter_by(action=AuditAction.CREDENTIAL_ROTATED, entity_id=dev.device_id).first()
        assert audit is not None

    # 9. Verify authentication with new key and credential_version=2 works
    hb_headers = sign_req(dev_id, new_key, "POST", "/api/v1/agents/heartbeat", b"", key_ver=2)
    hb_resp = client.post("/api/v1/agents/heartbeat", headers=hb_headers)
    assert hb_resp.status_code == 200

    # Old key is rejected
    old_hb_headers = sign_req(dev_id, old_key, "POST", "/api/v1/agents/heartbeat", b"", key_ver=1)
    old_hb_resp = client.post("/api/v1/agents/heartbeat", headers=old_hb_headers)
    assert old_hb_resp.status_code == 401


def test_recovery_unknown_device(client, app):
    """Unknown device evidence is rejected from recovery with 404."""
    new_key = Ed25519PrivateKey.generate()
    new_pub_raw = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b64 = base64.b64encode(new_pub_raw).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    pop_sig = make_proof_of_possession(new_key, new_pub_b64, ts, nonce)

    payload = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": pop_sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "NON-EXISTENT-UUID",
            "motherboard_serial_hash": "NON-EXISTENT-MB",
            "fingerprint": "fp-ghost",
        },
    }

    resp = client.post("/api/v1/agents/recover", json=payload)
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "unknown_device"


def test_recovery_clock_skew_and_replay(client, app):
    """Recovery endpoint enforces clock skew limits and replay defense."""
    new_key = Ed25519PrivateKey.generate()
    new_pub_raw = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b64 = base64.b64encode(new_pub_raw).decode("ascii")

    # 1. Clock skew
    skewed_ts = int(time.time()) - 500
    nonce = uuid.uuid4().hex
    pop_sig = make_proof_of_possession(new_key, new_pub_b64, skewed_ts, nonce)
    payload = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": pop_sig,
        "timestamp": skewed_ts,
        "nonce": nonce,
    }
    resp = client.post("/api/v1/agents/recover", json=payload)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "clock_skew"

    # 2. Replay
    valid_ts = int(time.time())
    fixed_nonce = uuid.uuid4().hex
    pop_sig2 = make_proof_of_possession(new_key, new_pub_b64, valid_ts, fixed_nonce)
    payload2 = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": pop_sig2,
        "timestamp": valid_ts,
        "nonce": fixed_nonce,
        "identity_evidence": {"machine_uuid_hash": "UUID-X"},
    }
    client.post("/api/v1/agents/recover", json=payload2)
    # The first one might fail with unknown_device or 404, but nonce is recorded
    resp2 = client.post("/api/v1/agents/recover", json=payload2)
    assert resp2.status_code == 400
    assert resp2.get_json()["error"] == "replay_detected"


def test_physical_verification_workflow(client, app):
    """Physical verification endpoint creates verification record, trusts evidence, and updates asset."""
    admin_headers = ensure_admin(app)

    # 1. Enroll a device using token
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="ASSET-VERIFY-001",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.PENDING_AGENT,
        )
        db.session.add(asset)
        db.session.flush()
        raw_tok, _tok_obj = create_token_for_asset(asset.id)
        db.session.commit()
        a_id = asset.asset_id

    dev_key = Ed25519PrivateKey.generate()
    dev_pub_raw = dev_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    dev_pub_b64 = base64.b64encode(dev_pub_raw).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    tok_sha = hashlib.sha256(raw_tok.encode("utf-8")).hexdigest()
    proof_msg = f"enroll\n{tok_sha}\n{ts}\n{nonce}".encode()
    pop_sig = base64.b64encode(dev_key.sign(proof_msg)).decode("ascii")

    enroll_payload = {
        "enrollment_token": raw_tok,
        "device_public_key": dev_pub_b64,
        "proof_of_possession": pop_sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-VERIFY-1",
            "bios_serial_hash": "BIOS-VERIFY-1",
            "fingerprint": "fp-verify-1",
        },
        "inventory": {
            "hostname": "verify-node-01",
            "os_summary": "Linux 6.8",
        },
        "os": {"family": "LINUX", "name": "Ubuntu", "version": "24.04"},
        "agent_instance_id": "inst-verify-01",
    }

    enroll_resp = client.post("/api/v1/agents/enroll", json=enroll_payload)
    assert enroll_resp.status_code == 200
    dev_id = enroll_resp.get_json()["device_id"]

    # Verify initial state: PENDING_VERIFICATION, evidence untrusted
    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.PENDING_VERIFICATION
        ev = DeviceIdentityEvidence.query.filter_by(device_id=dev.id).first()
        assert ev.trusted is False

    # 2. Admin performs physical verification
    verify_payload = {
        "verification_method": "SERIAL_CHECK",
        "observed_asset_tag": "ASSET-VERIFY-001",
        "observed_serial": "BIOS-VERIFY-1",
        "observed_location": "Science Hall 204",
        "notes": "Verified sticker matches serial and room location",
    }
    v_resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/verify",
        json=verify_payload,
        headers=admin_headers,
    )
    assert v_resp.status_code == 200
    v_data = v_resp.get_json()
    assert v_data["status"] == "verified"
    assert v_data["device_status"] == DeviceStatus.ACTIVE.value
    assert v_data["asset_id"] == a_id
    ver_id = v_data["verification_id"]

    # 3. Assert DB state
    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        assert dev.last_verified_at is not None

        # Evidence snapshot is now trusted
        ev = DeviceIdentityEvidence.query.filter_by(device_id=dev.id).first()
        assert ev.trusted is True

        # Link references verification record
        link = AssetDeviceLink.query.filter_by(device_id=dev.id, relationship_status=RelationshipStatus.ACTIVE).first()
        assert link.verification_id == ver_id

        # Verification audit record
        ver_row = db.session.get(Verification, ver_id)
        assert ver_row is not None
        assert ver_row.verified_by == "phase8_admin"
        assert ver_row.verification_method == VerificationMethod.SERIAL_CHECK
        assert ver_row.observed_location == "Science Hall 204"

        # Asset lifecycle and verification status updated
        asset = link.asset
        assert asset.verification_status == AssetVerificationStatus.VERIFIED
        assert asset.lifecycle_status == AssetLifecycleStatus.IN_SERVICE

        # Audit log entry exists
        audit = AuditLog.query.filter_by(action=AuditAction.ASSET_VERIFIED, entity_id=dev.device_id).first()
        assert audit is not None


def test_motherboard_replacement_workflow(client, app):
    """Motherboard replacement workflow: closes old link, retires old device, and re-pairs new device to same asset."""
    admin_headers = ensure_admin(app)
    dev1_id, asset_id, _ = create_asset_and_device(app, hostname="ws-mobo-01", mb_serial="MB-BROKEN-01")

    # 1. Admin triggers motherboard replacement for dev1
    replace_resp = client.post(
        f"/api/v1/admin/devices/{dev1_id}/replace-endpoint",
        json={"reason": "Motherboard died due to power surge, swapped board and CPU"},
        headers=admin_headers,
    )
    assert replace_resp.status_code == 200
    r_data = replace_resp.get_json()
    assert r_data["status"] == "endpoint_replaced"
    assert r_data["old_device_id"] == dev1_id
    assert r_data["asset_id"] == asset_id
    new_token = r_data["new_pairing_token"]
    assert new_token.startswith("PAIR-")

    # Check that old device is RETIRED and old link is CLOSED
    with app.app_context():
        old_dev = PhysicalDevice.query.filter_by(device_id=dev1_id).first()
        assert old_dev.status == DeviceStatus.RETIRED

        asset = Asset.query.filter_by(asset_id=asset_id).first()
        assert len(asset.links) == 1
        assert asset.links[0].relationship_status == RelationshipStatus.CLOSED
        assert asset.links[0].reason == "Motherboard died due to power surge, swapped board and CPU"
        assert asset.links[0].unlinked_at is not None

    # 2. New endpoint with replaced motherboard enrolls using the new pairing token
    dev2_key = Ed25519PrivateKey.generate()
    dev2_pub_raw = dev2_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    dev2_pub_b64 = base64.b64encode(dev2_pub_raw).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    tok_sha = hashlib.sha256(new_token.encode("utf-8")).hexdigest()
    proof_msg = f"enroll\n{tok_sha}\n{ts}\n{nonce}".encode()
    pop_sig = base64.b64encode(dev2_key.sign(proof_msg)).decode("ascii")

    enroll_payload = {
        "enrollment_token": new_token,
        "device_public_key": dev2_pub_b64,
        "proof_of_possession": pop_sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-NEW-MOBO-999",
            "motherboard_serial_hash": "MB-REPLACEMENT-999",
            "fingerprint": "fp-new-mobo",
        },
        "inventory": {
            "hostname": "ws-mobo-01",
            "os_summary": "Ubuntu 24.04",
        },
        "os": {"family": "LINUX", "name": "Ubuntu", "version": "24.04"},
        "agent_instance_id": "inst-new-mobo-agent",
    }

    enroll_resp = client.post("/api/v1/agents/enroll", json=enroll_payload)
    assert enroll_resp.status_code == 200
    dev2_id = enroll_resp.get_json()["device_id"]
    assert dev2_id != dev1_id

    # 3. Assert asset history: retains Asset ID, exactly two links in history
    with app.app_context():
        asset = Asset.query.filter_by(asset_id=asset_id).first()
        assert len(asset.links) == 2

        closed_links = [lk for lk in asset.links if lk.relationship_status == RelationshipStatus.CLOSED]
        active_links = [lk for lk in asset.links if lk.relationship_status == RelationshipStatus.ACTIVE]

        assert len(closed_links) == 1
        assert closed_links[0].device.device_id == dev1_id

        assert len(active_links) == 1
        assert active_links[0].device.device_id == dev2_id


def test_replace_endpoint_fails_if_no_active_link(client, app):
    """Calling replace-endpoint on an unlinked device returns 400."""
    admin_headers = ensure_admin(app)
    with app.app_context():
        dev = PhysicalDevice(
            device_id=generate_device_id(),
            device_public_key="some-key",
            status=DeviceStatus.UNCLAIMED,
        )
        db.session.add(dev)
        db.session.commit()
        dev_id = dev.device_id

    resp = client.post(f"/api/v1/admin/devices/{dev_id}/replace-endpoint", headers=admin_headers)
    assert resp.status_code == 400
    assert "no active asset link" in resp.get_json()["message"]


def test_approve_recovery_fails_if_no_pending_request(client, app):
    """Calling approve-recovery on a device without a pending recovery request returns 404."""
    admin_headers = ensure_admin(app)
    dev_id, _, _ = create_asset_and_device(app)

    resp = client.post(f"/api/v1/admin/devices/{dev_id}/approve-recovery", headers=admin_headers)
    assert resp.status_code == 404
    assert "No pending recovery request found" in resp.get_json()["message"]
