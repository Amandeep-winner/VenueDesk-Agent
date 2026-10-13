"""End-to-End Test Suite: Dual-Boot OS Isolation, Reinstall, and Recovery (Phase 4).

Validates the target model:
Asset -- (1 ACTIVE link) -- PhysicalDevice --+-- OSInstallation (Windows W1)
                                             +-- OSInstallation (Linux L1 -> L2)

Tests:
1. Full sequence:
   - Enroll physical device (asset token) -> Windows W1
   - Enroll Linux L1 via device-scoped OS token -> same device_id, 1 active link, 2 active OS installations
   - Windows reports again -> still W1, not 'first row'
   - Reinstall Linux -> new key, L2 os_installation_id, recovery request created, no new device/asset
   - Without approval L2 agent is denied jobs/telemetry
   - Admin approves -> L2 ACTIVE, L1 HISTORICAL, W1 ACTIVE, credential version incremented, audit rows present
2. test_ambiguous_candidates_require_manual_pairing
3. test_recovery_never_uses_similarity_alone
4. test_device_scoped_token_cannot_be_used_for_other_device
5. test_os_count_is_derived
"""
import base64
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime

import pytest
from app import create_app
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    AuditAction,
    AuditLog,
    DeviceCredential,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceRecoveryRequest,
    DeviceStatus,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    User,
    UserRole,
    generate_next_asset_id,
)
from app.security.tokens import create_token_for_asset, create_token_for_device
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def app():
    """Create Flask application instance for dual-boot & recovery E2E tests."""
    app_instance = create_app("testing")
    with app_instance.app_context():
        db.create_all()
        admin = User(username="dual_admin", role=UserRole.INFRA_ADMIN)
        admin.set_password("adminpassword123")
        db.session.add(admin)
        db.session.commit()
        yield app_instance
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


from app.security.signatures import canonical_string


def sign_req(dev_id: str, key: Ed25519PrivateKey, method: str, path: str, body: bytes, key_ver: int = 1) -> dict[str, str]:
    """Helper generating standard X-Device-ID and Ed25519 signature headers."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canonical = canonical_string(method, path, ts, nonce, body)
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": str(key_ver),
        "X-Signature": sig,
    }


def admin_auth_header() -> dict[str, str]:
    """Basic auth header for dual_admin."""
    creds = base64.b64encode(b"dual_admin:adminpassword123").decode("ascii")
    return {"Authorization": f"Basic {creds}"}


def test_dual_boot_reinstall_recovery_sequence(client, app):
    """Full sequence: Windows W1 -> Linux L1 -> Windows W1 -> Linux L2 Reinstall -> Recovery -> Approval."""
    # -------------------------------------------------------------------------
    # 1. Enroll physical computer (asset token)
    # -------------------------------------------------------------------------
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="ASSET-DUAL-01",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)
        db.session.commit()
        asset_pk = asset.id
        asset_id_str = asset.asset_id

        raw_asset_token, _ = create_token_for_asset(asset_pk)
        db.session.commit()

    # Generate Windows key and proof of possession
    win_key = Ed25519PrivateKey.generate()
    win_pub_b64 = base64.b64encode(
        win_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    tok_sha = hashlib.sha256(raw_asset_token.strip().encode("utf-8")).hexdigest()
    win_pop = base64.b64encode(win_key.sign(f"enroll\n{tok_sha}\n{ts}\n{nonce}".encode())).decode("ascii")

    w1_os_id = "w1-" + uuid.uuid4().hex[:12]
    w1_payload = {
        "enrollment_token": raw_asset_token,
        "device_public_key": win_pub_b64,
        "proof_of_possession": win_pop,
        "timestamp": ts,
        "nonce": nonce,
        "os_installation_id": w1_os_id,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-DUAL-HOST-01",
            "motherboard_serial_hash": "MB-DUAL-HOST-01",
            "bios_serial_hash": "BIOS-DUAL-HOST-01",
            "cpu_signature": "AMD Ryzen 9 7900X",
            "fingerprint": "fp-dual-host-01",
            "fingerprint_version": 1,
        },
        "inventory": {
            "hostname": "dual-host-win",
            "ip_addresses": ["192.168.1.50"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "ram_total_mb": 32768,
        },
        "os": {
            "family": "WINDOWS",
            "name": "Windows 11 Enterprise",
            "version": "23H2",
            "architecture": "x86_64",
            "os_machine_id_hash": "win-machine-guid-01",
            "os_installation_id": w1_os_id,
        },
        "agent_instance_id": "inst-win-01",
    }

    resp = client.post("/api/v1/agents/enroll", json=w1_payload)
    assert resp.status_code == 200
    enroll_data = resp.get_json()
    device_id = enroll_data["device_id"]

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        assert device is not None
        assert device.active_os_count == 1
        links = AssetDeviceLink.query.filter_by(device_id=device.id, relationship_status=RelationshipStatus.ACTIVE).all()
        assert len(links) == 1
        assert links[0].asset_id == asset_pk

        # Activate device for operational state
        device.status = DeviceStatus.ACTIVE
        # Mark initial evidence trusted
        ev = DeviceIdentityEvidence.query.filter_by(device_id=device.id).first()
        ev.trusted = True
        db.session.commit()

    # -------------------------------------------------------------------------
    # 2. Report Windows inventory (os_installation_id W1)
    # -------------------------------------------------------------------------
    w1_inv_body = json.dumps({
        "os_installation_id": w1_os_id,
        "inventory": {"hostname": "dual-host-win", "ip_addresses": ["192.168.1.50"]},
        "os": {"family": "WINDOWS", "name": "Windows 11 Enterprise", "version": "23H2", "os_installation_id": w1_os_id},
    }, separators=(",", ":")).encode("utf-8")
    headers = sign_req(device_id, win_key, "POST", "/api/v1/agents/inventory", w1_inv_body, key_ver=1)
    headers["Content-Type"] = "application/json"
    resp = client.post("/api/v1/agents/inventory", data=w1_inv_body, headers=headers)
    assert resp.status_code == 200

    # -------------------------------------------------------------------------
    # 3. Enroll Linux via device-scoped OS token; report Linux inventory (L1)
    # -------------------------------------------------------------------------
    # Admin generates device-scoped OS token
    resp_token = client.post(
        f"/api/v1/admin/devices/{device_id}/os-token",
        headers=admin_auth_header(),
        json={"ttl_hours": 24},
    )
    assert resp_token.status_code == 201
    os_token_data = resp_token.get_json()
    raw_os_token = os_token_data["raw_token"]
    assert os_token_data["scope"] == "DEVICE"
    assert os_token_data["device_id"] == device_id

    # Linux generates its own separate Ed25519 keypair
    linux_l1_key = Ed25519PrivateKey.generate()
    linux_l1_pub_b64 = base64.b64encode(
        linux_l1_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    ts_l1 = int(time.time())
    nonce_l1 = uuid.uuid4().hex
    tok_l1_sha = hashlib.sha256(raw_os_token.strip().encode("utf-8")).hexdigest()
    l1_pop = base64.b64encode(linux_l1_key.sign(f"enroll\n{tok_l1_sha}\n{ts_l1}\n{nonce_l1}".encode())).decode("ascii")

    l1_os_id = "l1-" + uuid.uuid4().hex[:12]
    l1_payload = {
        "enrollment_token": raw_os_token,
        "device_public_key": linux_l1_pub_b64,
        "proof_of_possession": l1_pop,
        "timestamp": ts_l1,
        "nonce": nonce_l1,
        "os_installation_id": l1_os_id,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-DUAL-HOST-01",
            "motherboard_serial_hash": "MB-DUAL-HOST-01",
            "bios_serial_hash": "BIOS-DUAL-HOST-01",
            "cpu_signature": "AMD Ryzen 9 7900X",
            "fingerprint": "fp-dual-host-01",
            "fingerprint_version": 1,
        },
        "inventory": {
            "hostname": "dual-host-linux",
            "ip_addresses": ["192.168.1.51"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "ram_total_mb": 32768,
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": "linux-machine-id-01",
            "os_installation_id": l1_os_id,
        },
        "agent_instance_id": "inst-linux-01",
    }

    resp_l1 = client.post("/api/v1/agents/enroll", json=l1_payload)
    assert resp_l1.status_code == 200
    assert resp_l1.get_json()["device_id"] == device_id

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        # Verify same physical device and same asset link
        assert device is not None
        assert PhysicalDevice.query.count() == 1
        assert Asset.query.count() == 1
        links = AssetDeviceLink.query.filter_by(relationship_status=RelationshipStatus.ACTIVE).all()
        assert len(links) == 1
        assert links[0].device_id == device.id
        assert links[0].asset_id == asset_pk

        # Two ACTIVE OSInstallations: Windows W1 and Linux L1
        active_os = OSInstallation.query.filter_by(device_id=device.id, status=OsInstallationStatus.ACTIVE).all()
        assert len(active_os) == 2
        os_ids = {o.os_installation_id for o in active_os}
        assert w1_os_id in os_ids
        assert l1_os_id in os_ids
        assert device.active_os_count == 2

        # OS_INSTALLATION_ADDED event recorded
        added_ev = DeviceEvent.query.filter_by(
            device_id=device.id,
            event_type=DeviceEventType.OS_INSTALLATION_ADDED,
        ).first()
        assert added_ev is not None

        # Two active credentials in device_credentials
        creds = DeviceCredential.query.filter_by(device_id=device.id, status="ACTIVE").all()
        assert len(creds) >= 2

    # Linux reports inventory L1 signed by its own key
    l1_inv_body = json.dumps({
        "os_installation_id": l1_os_id,
        "inventory": {"hostname": "dual-host-linux", "ip_addresses": ["192.168.1.51"]},
        "os": {"family": "LINUX", "name": "Ubuntu", "version": "24.04", "os_installation_id": l1_os_id},
    }, separators=(",", ":")).encode("utf-8")
    headers = sign_req(device_id, linux_l1_key, "POST", "/api/v1/agents/inventory", l1_inv_body, key_ver=1)
    headers["Content-Type"] = "application/json"
    resp = client.post("/api/v1/agents/inventory", data=l1_inv_body, headers=headers)
    assert resp.status_code == 200

    # -------------------------------------------------------------------------
    # 4. Windows reports again -> still W1, not "first row"
    # -------------------------------------------------------------------------
    time.sleep(0.01)
    hb_body = json.dumps({
        "os_installation_id": w1_os_id,
        "agent_instance_id": "inst-win-01",
        "status": "ACTIVE",
    }, separators=(",", ":")).encode("utf-8")
    headers = sign_req(device_id, win_key, "POST", "/api/v1/agents/heartbeat", hb_body, key_ver=1)
    headers["Content-Type"] = "application/json"
    resp = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        w1_row = OSInstallation.query.filter_by(device_id=device.id, os_installation_id=w1_os_id).first()
        l1_row = OSInstallation.query.filter_by(device_id=device.id, os_installation_id=l1_os_id).first()
        assert w1_row.status == OsInstallationStatus.ACTIVE
        assert l1_row.status == OsInstallationStatus.ACTIVE
        # W1 was updated by the Windows heartbeat
        assert w1_row.last_seen >= l1_row.last_seen

    # -------------------------------------------------------------------------
    # 5. Reinstall Linux -> new key, new os_installation_id L2, recovery request created
    # -------------------------------------------------------------------------
    linux_l2_key = Ed25519PrivateKey.generate()
    linux_l2_pub_b64 = base64.b64encode(
        linux_l2_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    ts_l2 = int(time.time())
    nonce_l2 = uuid.uuid4().hex
    l2_pop = base64.b64encode(linux_l2_key.sign(f"recover\n{linux_l2_pub_b64}\n{ts_l2}\n{nonce_l2}".encode())).decode("ascii")

    l2_os_id = "l2-" + uuid.uuid4().hex[:12]
    l2_payload = {
        "device_public_key": linux_l2_pub_b64,
        "proof_of_possession": l2_pop,
        "timestamp": ts_l2,
        "nonce": nonce_l2,
        "os_installation_id": l2_os_id,
        "agent_instance_id": "inst-linux-02",
        "identity_evidence": {
            "machine_uuid_hash": "UUID-DUAL-HOST-01",
            "motherboard_serial_hash": "MB-DUAL-HOST-01",
            "bios_serial_hash": "BIOS-DUAL-HOST-01",
            "cpu_signature": "AMD Ryzen 9 7900X",
            "fingerprint": "fp-dual-host-01",
            "fingerprint_version": 1,
        },
        "inventory": {
            "hostname": "dual-host-linux-reinstalled",
            "ip_addresses": ["192.168.1.52"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "ram_total_mb": 32768,
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": "linux-machine-id-02",
            "os_installation_id": l2_os_id,
        },
    }

    resp_rec = client.post("/api/v1/agents/recover", json=l2_payload)
    assert resp_rec.status_code == 200
    rec_result = resp_rec.get_json()
    assert rec_result["status"] == "pending_approval"
    assert rec_result["device_id"] == device_id

    with app.app_context():
        # Assert no new PhysicalDevice or Asset created
        assert PhysicalDevice.query.count() == 1
        assert Asset.query.count() == 1
        # Assert link unchanged
        active_link = AssetDeviceLink.query.filter_by(relationship_status=RelationshipStatus.ACTIVE).first()
        assert active_link.device.device_id == device_id
        assert active_link.asset.asset_id == asset_id_str

        # Device is PENDING_REVERIFICATION
        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        assert device.status == DeviceStatus.PENDING_REVERIFICATION

        # Recovery request pending
        rec = DeviceRecoveryRequest.query.filter_by(device_id=device.id, status="PENDING").first()
        assert rec is not None
        assert rec.new_public_key == linux_l2_pub_b64

    # -------------------------------------------------------------------------
    # 6. Without approval the L2 agent is denied jobs/telemetry
    # -------------------------------------------------------------------------
    telemetry_body = json.dumps({
        "samples": [{"metric": "cpu", "value": 15.0}],
    }, separators=(",", ":")).encode("utf-8")
    headers_l2_denied = sign_req(device_id, linux_l2_key, "POST", "/api/v1/agents/telemetry", telemetry_body, key_ver=1)
    headers_l2_denied["Content-Type"] = "application/json"
    r_denied = client.post("/api/v1/agents/telemetry", data=telemetry_body, headers=headers_l2_denied)
    assert r_denied.status_code == 401

    # -------------------------------------------------------------------------
    # 7. Admin approves -> L2 ACTIVE, L1 HISTORICAL, old credential revoked, version bumped
    # -------------------------------------------------------------------------
    r_appr = client.post(
        f"/api/v1/admin/devices/{device_id}/approve-recovery",
        headers=admin_auth_header(),
        json={"reason": "Physical verification confirmed reinstalled Linux partition"},
    )
    assert r_appr.status_code == 200
    appr_data = r_appr.get_json()
    assert appr_data["status"] == "approved"
    new_version = appr_data["credential_version"]
    assert new_version == 2

    with app.app_context():
        device = PhysicalDevice.query.filter_by(device_id=device_id).first()
        assert device.status == DeviceStatus.ACTIVE
        assert device.credential_version == 2

        # L2 is ACTIVE
        l2_os = OSInstallation.query.filter_by(device_id=device.id, os_installation_id=l2_os_id).first()
        assert l2_os is not None
        assert l2_os.status == OsInstallationStatus.ACTIVE

        # L1 is HISTORICAL
        l1_os = OSInstallation.query.filter_by(device_id=device.id, os_installation_id=l1_os_id).first()
        assert l1_os is not None
        assert l1_os.status == OsInstallationStatus.HISTORICAL

        # Windows W1 remains ACTIVE throughout!
        w1_os = OSInstallation.query.filter_by(device_id=device.id, os_installation_id=w1_os_id).first()
        assert w1_os is not None
        assert w1_os.status == OsInstallationStatus.ACTIVE

        # Exactly 2 active OS installations: W1 and L2
        assert device.active_os_count == 2

        # L1 credential revoked in device_credentials
        l1_cred = DeviceCredential.query.filter_by(device_id=device.id, os_installation_id=l1_os_id).first()
        if l1_cred:
            assert l1_cred.status == "REVOKED"

        # L2 credential is active with credential_version == 2
        l2_cred = DeviceCredential.query.filter_by(device_id=device.id, os_installation_id=l2_os_id).first()
        assert l2_cred is not None
        assert l2_cred.status == "ACTIVE"
        assert l2_cred.credential_version == 2

        # Audit logs recorded
        logs = AuditLog.query.filter_by(entity_id=device_id).all()
        actions = [log.action for log in logs]
        assert AuditAction.CREDENTIAL_ROTATED in actions
        assert AuditAction.HARDWARE_CHANGE_APPROVED in actions

    # L2 can now successfully authenticate with key_version 2
    hb_l2 = json.dumps({
        "os_installation_id": l2_os_id,
        "status": "ACTIVE",
    }, separators=(",", ":")).encode("utf-8")
    headers_l2_allowed = sign_req(device_id, linux_l2_key, "POST", "/api/v1/agents/heartbeat", hb_l2, key_ver=2)
    headers_l2_allowed["Content-Type"] = "application/json"
    r_l2_hb = client.post("/api/v1/agents/heartbeat", data=hb_l2, headers=headers_l2_allowed)
    assert r_l2_hb.status_code == 200


def test_ambiguous_candidates_require_manual_pairing(client, app):
    """Multiple candidate devices matching identical evidence return 409 and require manual review."""
    with app.app_context():
        # Setup two distinct physical devices with identical hardware evidence
        for idx in ("A", "B"):
            asset = Asset(
                asset_id=generate_next_asset_id(db.session),
                asset_tag=f"TAG-AMBIG-{idx}",
                asset_type=AssetType.DESKTOP,
                lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
            )
            db.session.add(asset)
            db.session.flush()

            dev = PhysicalDevice(
                device_id=f"VD-DEVICE-AMBIG-{idx}",
                device_public_key=f"pubkey-ambig-{idx}",
                credential_version=1,
                status=DeviceStatus.ACTIVE,
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
            )
            db.session.add(dev)
            db.session.flush()

            link = AssetDeviceLink(
                asset_id=asset.id,
                device_id=dev.id,
                relationship_status=RelationshipStatus.ACTIVE,
                linked_at=datetime.now(UTC),
                linked_by="admin",
            )
            db.session.add(link)

            ev = DeviceIdentityEvidence(
                device_id=dev.id,
                machine_uuid_hash="UUID-SHARED-CLONE",
                motherboard_serial_hash="MB-SHARED-CLONE",
                bios_serial_hash="BIOS-SHARED-CLONE",
                cpu_signature="Generic QuadCore",
                fingerprint="fp-shared-clone",
                fingerprint_version=1,
                captured_at=datetime.now(UTC),
                evidence_version=1,
                trusted=True,
            )
            db.session.add(ev)

        db.session.commit()

    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    pop = base64.b64encode(key.sign(f"recover\n{pub_b64}\n{ts}\n{nonce}".encode())).decode("ascii")

    payload = {
        "device_public_key": pub_b64,
        "proof_of_possession": pop,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-SHARED-CLONE",
            "motherboard_serial_hash": "MB-SHARED-CLONE",
            "bios_serial_hash": "BIOS-SHARED-CLONE",
            "cpu_signature": "Generic QuadCore",
            "fingerprint": "fp-shared-clone",
            "fingerprint_version": 1,
        },
        "inventory": {"hostname": "ambiguous-pc"},
    }

    resp = client.post("/api/v1/agents/recover", json=payload)
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "ambiguous_match"


def test_recovery_never_uses_similarity_alone(client, app):
    """High hardware similarity alone NEVER automatically recovers or links a device without approval."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TAG-SIMILAR-01",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)
        db.session.flush()

        dev = PhysicalDevice(
            device_id="VD-DEVICE-SIMILAR-01",
            device_public_key="pubkey-sim-orig",
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db.session.add(dev)
        db.session.flush()

        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=dev.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_at=datetime.now(UTC),
            linked_by="admin",
        )
        db.session.add(link)

        ev = DeviceIdentityEvidence(
            device_id=dev.id,
            machine_uuid_hash="UUID-PERFECT-MATCH",
            motherboard_serial_hash="MB-PERFECT-MATCH",
            bios_serial_hash="BIOS-PERFECT-MATCH",
            cpu_signature="Core i9 13900K",
            fingerprint="fp-perfect-match",
            fingerprint_version=1,
            captured_at=datetime.now(UTC),
            evidence_version=1,
            trusted=True,
        )
        db.session.add(ev)
        db.session.commit()

    new_key = Ed25519PrivateKey.generate()
    new_pub_b64 = base64.b64encode(new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    pop = base64.b64encode(new_key.sign(f"recover\n{new_pub_b64}\n{ts}\n{nonce}".encode())).decode("ascii")

    # 100% matching hardware evidence
    payload = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": pop,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-PERFECT-MATCH",
            "motherboard_serial_hash": "MB-PERFECT-MATCH",
            "bios_serial_hash": "BIOS-PERFECT-MATCH",
            "cpu_signature": "Core i9 13900K",
            "fingerprint": "fp-perfect-match",
            "fingerprint_version": 1,
        },
        "inventory": {"hostname": "similar-pc"},
    }

    resp = client.post("/api/v1/agents/recover", json=payload)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "pending_approval"

    with app.app_context():
        # Candidate MUST be in PENDING_REVERIFICATION, NEVER ACTIVE
        dev_check = PhysicalDevice.query.filter_by(device_id="VD-DEVICE-SIMILAR-01").first()
        assert dev_check.status == DeviceStatus.PENDING_REVERIFICATION
        # Credential version is not changed before approval
        assert dev_check.credential_version == 1
        assert dev_check.device_public_key == "pubkey-sim-orig"


def test_device_scoped_token_cannot_be_used_for_other_device(client, app):
    """Device-scoped token used with conflicting hardware evidence enters review and does not auto-activate."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TAG-TOKEN-SCOPED-01",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)
        db.session.flush()

        dev = PhysicalDevice(
            device_id="VD-DEVICE-SCOPED-01",
            device_public_key="pubkey-scoped-01",
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db.session.add(dev)
        db.session.flush()

        ev = DeviceIdentityEvidence(
            device_id=dev.id,
            machine_uuid_hash="UUID-LEGIT-DEV",
            motherboard_serial_hash="MB-LEGIT-DEV",
            bios_serial_hash="BIOS-LEGIT-DEV",
            cpu_signature="Intel i5",
            fingerprint="fp-legit-dev",
            fingerprint_version=1,
            captured_at=datetime.now(UTC),
            evidence_version=1,
            trusted=True,
        )
        db.session.add(ev)

        raw_token, _ = create_token_for_device(dev.id)
        db.session.commit()

    # Attacker machine B uses dev's token with completely different hardware
    key_b = Ed25519PrivateKey.generate()
    pub_b_b64 = base64.b64encode(key_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    tok_sha = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
    pop_b = base64.b64encode(key_b.sign(f"enroll\n{tok_sha}\n{ts}\n{nonce}".encode())).decode("ascii")

    payload_b = {
        "enrollment_token": raw_token,
        "device_public_key": pub_b_b64,
        "proof_of_possession": pop_b,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-ATTACKER-DEV",
            "motherboard_serial_hash": "MB-ATTACKER-DEV",
            "bios_serial_hash": "BIOS-ATTACKER-DEV",
            "cpu_signature": "Attacker CPU",
            "fingerprint": "fp-attacker",
            "fingerprint_version": 1,
        },
        "inventory": {"hostname": "rogue-host"},
    }

    resp = client.post("/api/v1/agents/enroll", json=payload_b)
    assert resp.status_code == 200

    with app.app_context():
        # Device must have entered PENDING_REVERIFICATION due to anchor mismatch
        dev_check = PhysicalDevice.query.filter_by(device_id="VD-DEVICE-SCOPED-01").first()
        assert dev_check.status == DeviceStatus.PENDING_REVERIFICATION
        ev = DeviceEvent.query.filter_by(device_id=dev_check.id, event_type=DeviceEventType.IDENTITY_CHANGE_DETECTED).first()
        assert ev is not None


def test_os_count_is_derived(app):
    """OS count is derived dynamically from os_installations and NEVER stored as a column."""
    with app.app_context():
        table_columns = [c.name for c in PhysicalDevice.__table__.columns]
        assert "os_count" not in table_columns
        assert "active_os_count" not in table_columns

        dev = PhysicalDevice(
            device_id="VD-DEVICE-DERIVED-OS",
            device_public_key="pub-derived",
            credential_version=1,
            status=DeviceStatus.ACTIVE,
        )
        db.session.add(dev)
        db.session.flush()

        assert dev.active_os_count == 0

        os1 = OSInstallation(
            device_id=dev.id,
            os_installation_id="os-1",
            os_family=OsFamily.LINUX,
            os_name="Debian",
            os_version="12",
            architecture="x86_64",
            os_machine_id_hash="hash-1",
            agent_instance_id="inst-1",
            status=OsInstallationStatus.ACTIVE,
        )
        os2 = OSInstallation(
            device_id=dev.id,
            os_installation_id="os-2",
            os_family=OsFamily.WINDOWS,
            os_name="Windows",
            os_version="11",
            architecture="x86_64",
            os_machine_id_hash="hash-2",
            agent_instance_id="inst-2",
            status=OsInstallationStatus.HISTORICAL,
        )
        db.session.add_all([os1, os2])
        db.session.commit()

        # Exactly 1 active OS installation
        assert dev.active_os_count == 1
