"""Comprehensive End-to-End Test Suite: Full Endpoint Lifecycle (Phase 12).

Drives an in-process server through the complete endpoint lifecycle:
1. Create Asset (Institutional Asset Registry)
2. Generate Pairing Token (Scoped Single-Use Secret)
3. Enroll Endpoint (Proof of Possession + Hardware Evidence)
4. Verify Device (Physical Auditor Confirmation Spec §57)
5. Heartbeat & Telemetry (Signed Telemetry Time Series)
6. Component & Network Changes (IP / Hostname / GPU / SSD Changes)
7. OS Reinstall Recovery (Key Rotation + Historical OS Archiving)
8. Dual-Boot Second OS (Multi-OS to Single Physical Device Mapping)
9. Motherboard Replacement (Chassis Retainment & Re-Pairing)
10. Clone / Duplicate Detection (Suspension on Cloned Credentials)
11. Device Revocation (Definitive Cryptographic Termination)
"""

import base64
import hashlib
import json
import time
import uuid

import pytest
from app import create_app
from app.extensions import db
from app.models import (
    Asset,
    AssetLifecycleStatus,
    AssetType,
    AssetVerificationStatus,
    DeviceEvent,
    DeviceEventType,
    DeviceStatus,
    EventSeverity,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    User,
    UserRole,
    generate_next_asset_id,
)
from app.security.tokens import create_token_for_asset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def app():
    """Create Flask application instance for E2E tests."""
    app_instance = create_app("testing")
    with app_instance.app_context():
        db.create_all()
        # Seed an admin user for admin actions
        admin = User(username="lifecycle_admin", role=UserRole.INFRA_ADMIN)
        admin.set_password("adminpassword123")
        db.session.add(admin)
        db.session.commit()
        yield app_instance
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def sign_req(
    dev_id: str,
    key: Ed25519PrivateKey,
    method: str,
    path: str,
    body: bytes,
    key_ver: int = 1,
) -> dict[str, str]:
    """Helper generating standard X-Device-ID and Ed25519 signature headers."""
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


def admin_auth_header() -> dict[str, str]:
    """Basic auth header for lifecycle_admin."""
    creds = base64.b64encode(b"lifecycle_admin:adminpassword123").decode("ascii")
    return {"Authorization": f"Basic {creds}"}


def test_full_endpoint_lifecycle_e2e(client, app):
    """Drive an endpoint through the complete lifecycle from birth to decommissioning."""
    # =========================================================================
    # STAGE 1: Create Institutional Asset
    # =========================================================================
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="CS-LAB-042",
            asset_type=AssetType.DESKTOP,
            location_label="Computer Science Lab 3, Desk 12",
            lifecycle_status=AssetLifecycleStatus.DRAFT,
            verification_status=AssetVerificationStatus.UNVERIFIED,
        )
        db.session.add(asset)
        db.session.commit()
        asset_id = asset.asset_id
        asset_pk = asset.id

    assert asset_id.startswith("VD-ASSET-")

    # =========================================================================
    # STAGE 2: Generate Pairing Token
    # =========================================================================
    from app.api.agents import reset_rate_limits

    reset_rate_limits()

    with app.app_context():
        raw_token, _tok_row = create_token_for_asset(
            asset_pk, created_by="lifecycle_admin"
        )
        db.session.commit()
    assert raw_token.startswith("PAIR-")

    # =========================================================================
    # STAGE 3: Agent Initial Enrollment
    # =========================================================================
    agent_key_v1 = Ed25519PrivateKey.generate()
    pub_raw_v1 = agent_key_v1.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64_v1 = base64.b64encode(pub_raw_v1).decode("ascii")

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    enroll_ts = int(time.time())
    enroll_nonce = uuid.uuid4().hex
    enroll_proof = base64.b64encode(
        agent_key_v1.sign(f"enroll\n{token_hash}\n{enroll_ts}\n{enroll_nonce}".encode())
    ).decode("ascii")

    salt = b"venuedesk-default-salt-32-chars-long!"

    def h_ev(val):
        import hmac

        return hmac.new(salt, val.encode(), hashlib.sha256).hexdigest()

    evidence_v1 = {
        "machine_uuid_hash": h_ev("uuid-motherboard-chassis-42"),
        "bios_serial_hash": h_ev("bios-serial-42"),
        "motherboard_serial_hash": h_ev("mobo-serial-42"),
        "cpu_signature": "intel core i7-12700k",
        "gpu_signature": "nvidia geforce rtx 3070",
        "disk_identity_hash": h_ev("samsung-ssd-980-1tb"),
        "network_identity_hash": h_ev("00:11:22:33:44:55"),
        "tpm_identity": h_ev("tpm-slb9670"),
        "fingerprint": "fingerprint-baseline-v1",
        "fingerprint_version": 1,
    }

    enroll_payload = {
        "enrollment_token": raw_token,
        "device_public_key": pub_b64_v1,
        "proof_of_possession": enroll_proof,
        "timestamp": enroll_ts,
        "nonce": enroll_nonce,
        "identity_evidence": evidence_v1,
        "inventory": {
            "hostname": "cs-lab-pc42",
            "ip_addresses": ["10.0.10.42"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "cpu_model": "Intel Core i7-12700K",
            "cpu_cores": 12,
            "ram_total_mb": 32768,
            "gpus": ["NVIDIA GeForce RTX 3070"],
            "disks": ["Samsung SSD 980 1TB"],
            "os_summary": "Ubuntu 24.04 LTS",
            "bios_version": "1.4.0",
            "tpm_present": True,
            "agent_version": "0.1.0",
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": h_ev("mid-ubuntu-42"),
        },
        "agent_version": "0.1.0",
        "agent_instance_id": "agent-inst-ubuntu-42",
    }

    enroll_resp = client.post("/api/v1/agents/enroll", json=enroll_payload)
    assert enroll_resp.status_code == 200
    enroll_data = enroll_resp.get_json()
    device_id = enroll_data["device_id"]
    assert device_id.startswith("VD-DEVICE-")
    assert enroll_data["status"] == "PENDING_VERIFICATION"
    assert enroll_data["asset_id"] == asset_id

    # Verify atomic single-use: token cannot be reused
    re_enroll = client.post("/api/v1/agents/enroll", json=enroll_payload)
    assert re_enroll.status_code == 400

    # =========================================================================
    # STAGE 4: Physical Device Verification (Spec §57)
    # =========================================================================
    verify_payload = {
        "verification_method": "ADMIN_CONFIRMATION",
        "observed_asset_tag": "CS-LAB-042",
        "observed_serial": "SN-DELL-OPTIPLEX-42",
        "observed_location": "CS Lab 3, Desk 12",
        "notes": "Audited physical barcode and chassis serial.",
    }
    verify_resp = client.post(
        f"/api/v1/admin/devices/{device_id}/verify",
        json=verify_payload,
        headers=admin_auth_header(),
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.get_json()
    assert v_data["status"] == "verified"
    assert v_data["device_status"] == "ACTIVE"

    # Verify DB state: asset is IN_SERVICE, VERIFIED
    with app.app_context():
        dev_row = PhysicalDevice.query.filter_by(device_id=device_id).first()
        assert dev_row.status == DeviceStatus.ACTIVE
        assert dev_row.last_verified_at is not None
        active_l = next(
            l
            for l in dev_row.links
            if l.relationship_status == RelationshipStatus.ACTIVE
        )
        assert active_l.asset.lifecycle_status == AssetLifecycleStatus.IN_SERVICE
        assert active_l.asset.verification_status == AssetVerificationStatus.VERIFIED

    # =========================================================================
    # STAGE 5: Authenticated Heartbeat & Telemetry Ingestion
    # =========================================================================
    hb_body = json.dumps({"agent_instance_id": "agent-inst-ubuntu-42"}).encode()
    hb_headers = sign_req(
        device_id, agent_key_v1, "POST", "/api/v1/agents/heartbeat", hb_body
    )
    hb_headers["Content-Type"] = "application/json"
    hb_resp = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=hb_headers)
    assert hb_resp.status_code == 200
    assert "server_time" in hb_resp.get_json()

    # Telemetry batch ingestion
    telem_samples = [
        {
            "timestamp": int(time.time()) - 30,
            "cpu_percent": 18.5,
            "memory_percent": 44.0,
            "disk_percent": 35.0,
            "network_rx": 10240,
            "network_tx": 5120,
            "uptime": 3600,
        },
        {
            "timestamp": int(time.time()),
            "cpu_percent": 24.0,
            "memory_percent": 45.5,
            "disk_percent": 35.0,
            "network_rx": 20480,
            "network_tx": 10240,
            "uptime": 3630,
        },
    ]
    telem_body = json.dumps({"samples": telem_samples}).encode()
    telem_headers = sign_req(
        device_id, agent_key_v1, "POST", "/api/v1/agents/telemetry", telem_body
    )
    telem_headers["Content-Type"] = "application/json"
    telem_resp = client.post(
        "/api/v1/agents/telemetry", data=telem_body, headers=telem_headers
    )
    assert telem_resp.status_code == 200
    assert telem_resp.get_json()["count"] == 2

    # =========================================================================
    # STAGE 6: Component & Network Changes (Reconciliation)
    # =========================================================================
    # Workstation moved to a new IP, upgraded to RTX 4080, and secondary SSD added
    updated_evidence = dict(evidence_v1)
    updated_evidence["gpu_signature"] = "nvidia geforce rtx 4080"
    updated_evidence["disk_identity_hash"] = h_ev("crucial-t700-2tb")
    updated_evidence["fingerprint"] = "fingerprint-upgraded-components"

    updated_inv = dict(enroll_payload["inventory"])
    updated_inv["hostname"] = "cs-lab-pc42-upgraded"
    updated_inv["ip_addresses"] = ["10.0.10.99"]
    updated_inv["gpus"] = ["NVIDIA GeForce RTX 4080"]
    updated_inv["disks"] = ["Crucial T700 2TB"]

    inv_body = json.dumps(
        {
            "inventory": updated_inv,
            "identity_evidence": updated_evidence,
            "os": enroll_payload["os"],
        }
    ).encode()
    inv_headers = sign_req(
        device_id, agent_key_v1, "POST", "/api/v1/agents/inventory", inv_body
    )
    inv_headers["Content-Type"] = "application/json"
    inv_resp = client.post(
        "/api/v1/agents/inventory", data=inv_body, headers=inv_headers
    )
    assert inv_resp.status_code == 200

    # Device remains ACTIVE (spec §4.6: component upgrades do not invalidate device)
    with app.app_context():
        dev_chk = PhysicalDevice.query.filter_by(device_id=device_id).first()
        assert dev_chk.status == DeviceStatus.ACTIVE
        events = [e.event_type for e in dev_chk.events]
        assert DeviceEventType.IP_CHANGED in events
        assert DeviceEventType.GPU_CHANGED in events
        assert DeviceEventType.DISK_CHANGED in events

    # =========================================================================
    # STAGE 7: OS Reinstall Recovery Workflow
    # =========================================================================
    # Target OS is wiped and reinstalled: agent starts with fresh key pair
    agent_key_v2 = Ed25519PrivateKey.generate()
    pub_raw_v2 = agent_key_v2.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64_v2 = base64.b64encode(pub_raw_v2).decode("ascii")

    reinstall_ts = int(time.time())
    reinstall_nonce = uuid.uuid4().hex
    reinstall_proof = base64.b64encode(
        agent_key_v2.sign(
            f"recover\n{pub_b64_v2}\n{reinstall_ts}\n{reinstall_nonce}".encode()
        )
    ).decode("ascii")

    recover_payload = {
        "device_public_key": pub_b64_v2,
        "proof_of_possession": reinstall_proof,
        "timestamp": reinstall_ts,
        "nonce": reinstall_nonce,
        "identity_evidence": evidence_v1,  # Same hardware anchors!
        "agent_instance_id": "agent-inst-ubuntu-reinstalled",
        "inventory": enroll_payload["inventory"],
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04.1",
            "architecture": "x86_64",
            "os_machine_id_hash": h_ev("mid-ubuntu-reinstalled"),
        },
    }

    rec_resp = client.post("/api/v1/agents/recover", json=recover_payload)
    assert rec_resp.status_code == 200
    rec_data = rec_resp.get_json()
    assert rec_data["status"] == "pending_approval"
    assert rec_data["device_id"] == device_id

    # Admin approves OS reinstall recovery via Admin API
    appr_resp = client.post(
        f"/api/v1/admin/devices/{device_id}/approve-recovery",
        headers=admin_auth_header(),
    )
    assert appr_resp.status_code == 200
    assert appr_resp.get_json()["credential_version"] == 2

    # Verify device now authenticates with the NEW key (v2)
    hb_v2_body = json.dumps(
        {"agent_instance_id": "agent-inst-ubuntu-reinstalled"}
    ).encode()
    hb_v2_headers = sign_req(
        device_id,
        agent_key_v2,
        "POST",
        "/api/v1/agents/heartbeat",
        hb_v2_body,
        key_ver=2,
    )
    hb_v2_headers["Content-Type"] = "application/json"
    hb_v2_resp = client.post(
        "/api/v1/agents/heartbeat", data=hb_v2_body, headers=hb_v2_headers
    )
    assert hb_v2_resp.status_code == 200

    # Old key v1 must be rejected
    hb_old_headers = sign_req(
        device_id,
        agent_key_v1,
        "POST",
        "/api/v1/agents/heartbeat",
        hb_v2_body,
        key_ver=1,
    )
    hb_old_headers["Content-Type"] = "application/json"
    hb_old_resp = client.post(
        "/api/v1/agents/heartbeat", data=hb_v2_body, headers=hb_old_headers
    )
    assert hb_old_resp.status_code == 401

    # Verify OS installations: prior OS is HISTORICAL, new is ACTIVE
    with app.app_context():
        os_list = OSInstallation.query.filter_by(device_id=dev_chk.id).all()
        assert len(os_list) >= 2
        statuses = {o.status for o in os_list}
        assert OsInstallationStatus.HISTORICAL in statuses
        assert OsInstallationStatus.ACTIVE in statuses

    # =========================================================================
    # STAGE 8: Dual-Boot Second Operating System (Spec §43 & §66)
    # =========================================================================
    # Machine boots into Windows partition on the same physical hardware:
    # Modeled as one PhysicalDevice + multiple OSInstallation rows.
    win_payload = {
        "inventory": enroll_payload["inventory"],
        "os": {
            "family": "WINDOWS",
            "name": "Windows 11 Pro",
            "version": "23H2",
            "architecture": "x86_64",
            "os_machine_id_hash": h_ev("mid-windows-dualboot"),
        },
        "agent_instance_id": "agent-inst-win-dualboot",
    }
    win_body = json.dumps(win_payload).encode("utf-8")
    win_headers = sign_req(
        device_id, agent_key_v2, "POST", "/api/v1/agents/inventory", win_body, key_ver=2
    )
    win_headers["Content-Type"] = "application/json"
    win_resp = client.post(
        "/api/v1/agents/inventory", data=win_body, headers=win_headers
    )
    assert win_resp.status_code == 200

    # Verify both Linux and Windows OSInstallation records exist under same PhysicalDevice
    with app.app_context():
        dual_dev = PhysicalDevice.query.filter_by(device_id=device_id).first()
        os_list = OSInstallation.query.filter_by(device_id=dual_dev.id).all()
        fams = {o.os_family for o in os_list}
        assert "LINUX" in fams or OsFamily.LINUX in fams
        assert "WINDOWS" in fams or OsFamily.WINDOWS in fams

    # =========================================================================
    # STAGE 9: Motherboard Replacement Workflow
    # =========================================================================
    # Admin executes motherboard replacement: closes old link and generates token for original asset
    replace_resp = client.post(
        f"/api/v1/admin/devices/{device_id}/replace-endpoint",
        json={"reason": "Motherboard VRM failure warranty replacement"},
        headers=admin_auth_header(),
    )
    assert replace_resp.status_code == 200
    rep_data = replace_resp.get_json()
    new_pairing_token = rep_data["new_pairing_token"]
    assert rep_data["asset_id"] == asset_id

    # Enroll the new hardware motherboard replacement against original asset
    mobo_new_key = Ed25519PrivateKey.generate()
    mobo_new_pub_b64 = base64.b64encode(
        mobo_new_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode("ascii")

    mobo_ts = int(time.time())
    mobo_nonce = uuid.uuid4().hex
    mobo_tok_hash = hashlib.sha256(new_pairing_token.encode("utf-8")).hexdigest()
    mobo_proof = base64.b64encode(
        mobo_new_key.sign(f"enroll\n{mobo_tok_hash}\n{mobo_ts}\n{mobo_nonce}".encode())
    ).decode("ascii")

    evidence_new_mobo = dict(evidence_v1)
    evidence_new_mobo["motherboard_serial_hash"] = h_ev("new-mobo-serial-999")
    evidence_new_mobo["machine_uuid_hash"] = h_ev("new-uuid-replacement-999")

    mobo_enroll_payload = {
        "enrollment_token": new_pairing_token,
        "device_public_key": mobo_new_pub_b64,
        "proof_of_possession": mobo_proof,
        "timestamp": mobo_ts,
        "nonce": mobo_nonce,
        "identity_evidence": evidence_new_mobo,
        "inventory": enroll_payload["inventory"],
        "os": enroll_payload["os"],
        "agent_version": "0.1.0",
        "agent_instance_id": "inst-replacement-mobo",
    }
    mobo_resp = client.post("/api/v1/agents/enroll", json=mobo_enroll_payload)
    assert mobo_resp.status_code == 200
    new_device_id = mobo_resp.get_json()["device_id"]
    assert new_device_id != device_id  # Distinct PhysicalDevice row

    # Verify asset retains full historical continuity across hardware replacement
    with app.app_context():
        asset_obj = Asset.query.filter_by(asset_id=asset_id).first()
        assert len(asset_obj.links) >= 2
        link_statuses = [l.relationship_status for l in asset_obj.links]
        assert RelationshipStatus.CLOSED in link_statuses
        assert RelationshipStatus.ACTIVE in link_statuses

    # =========================================================================
    # STAGE 10: Clone / Duplicate Device Detection
    # =========================================================================
    # Simulate a cloned image where a second machine uses the new device's key
    # but presents a different agent_instance_id in rapid succession
    dup_body_1 = json.dumps({"agent_instance_id": "inst-replacement-mobo"}).encode()
    dup_h1 = sign_req(
        new_device_id, mobo_new_key, "POST", "/api/v1/agents/heartbeat", dup_body_1
    )
    dup_h1["Content-Type"] = "application/json"
    r1 = client.post("/api/v1/agents/heartbeat", data=dup_body_1, headers=dup_h1)
    assert r1.status_code == 200

    # Conflicting heartbeat from clone instance within window
    dup_body_2 = json.dumps(
        {"agent_instance_id": "rogue-cloned-image-instance"}
    ).encode()
    dup_h2 = sign_req(
        new_device_id, mobo_new_key, "POST", "/api/v1/agents/heartbeat", dup_body_2
    )
    dup_h2["Content-Type"] = "application/json"
    r2 = client.post("/api/v1/agents/heartbeat", data=dup_body_2, headers=dup_h2)
    assert r2.status_code == 403
    assert r2.get_json()["error"] == "device_suspended"

    # Check device was suspended and DUPLICATE_DEVICE_IDENTITY event recorded
    with app.app_context():
        susp_dev = PhysicalDevice.query.filter_by(device_id=new_device_id).first()
        assert susp_dev.status == DeviceStatus.SUSPENDED
        dup_ev = DeviceEvent.query.filter_by(
            device_id=susp_dev.id,
            event_type=DeviceEventType.DUPLICATE_DEVICE_IDENTITY,
        ).first()
        assert dup_ev is not None
        assert dup_ev.severity == EventSeverity.CRITICAL

    # =========================================================================
    # STAGE 11: Device Revocation
    # =========================================================================
    # Admin issues explicit revocation
    with app.app_context():
        susp_dev.status = DeviceStatus.REVOKED
        db.session.commit()

    # All subsequent requests from the revoked endpoint receive 403 device_blocked
    post_revoke_body = json.dumps(
        {"agent_instance_id": "inst-replacement-mobo"}
    ).encode()
    pr_headers = sign_req(
        new_device_id,
        mobo_new_key,
        "POST",
        "/api/v1/agents/heartbeat",
        post_revoke_body,
    )
    pr_headers["Content-Type"] = "application/json"
    pr_resp = client.post(
        "/api/v1/agents/heartbeat", data=post_revoke_body, headers=pr_headers
    )
    assert pr_resp.status_code == 403
    assert pr_resp.get_json()["error"] == "device_blocked"
