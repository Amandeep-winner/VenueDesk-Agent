"""Specification acceptance tests (§66) and identity reconciliation test suite."""

import base64
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
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
    generate_device_id,
    generate_next_asset_id,
)
from app.security.tokens import create_token_for_asset
from app.services.identity_service import (
    IdentityDecision,
    Observation,
    calculate_similarity_score,
    determine_device_identity,
)


def create_asset_and_device(
    app, hostname="workstation-01", mb_serial="MB-ORIG-1234", uuid_str="UUID-ORIG-5678"
):
    """Helper creating an institutional asset, physical device, active link, and trusted evidence."""
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
            bios_serial_hash="BIOS-111",
            cpu_signature="Intel i7",
            disk_identity_hash="DISK-PRIMARY",
            network_identity_hash="MAC-ETH0",
            tpm_identity="TPM-ORIG-1",
            fingerprint="fp-initial",
            captured_at=now,
            trusted=True,
        )
        db.session.add(evidence)

        inv = DeviceInventory(
            device_id=device.id,
            hostname=hostname,
            ip_addresses=["10.0.0.50"],
            mac_addresses=["00:11:22:33:44:55"],
            cpu_model="Intel i7-13700",
            cpu_cores=16,
            ram_total_mb=16384,
            gpus=["NVIDIA RTX 3070"],
            disks=["Samsung 970 EVO 500GB"],
            os_summary="Ubuntu 24.04",
            bios_version="v1.0",
            tpm_present=True,
            agent_version="0.1.0",
            updated_at=now,
        )
        db.session.add(inv)

        os_inst = OSInstallation(
            device_id=device.id,
            os_family=OsFamily.LINUX,
            os_name="Ubuntu",
            os_version="24.04",
            architecture="x86_64",
            os_machine_id_hash="mid-hash-01",
            agent_instance_id="inst-01",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)
        db.session.commit()

        a_id = asset.asset_id
        d_id = device.device_id

    return d_id, a_id, key


def sign_req(
    dev_id: str, key: Ed25519PrivateKey, method: str, path: str, body: bytes
) -> dict[str, str]:
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    b_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{b_hash}".encode()
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": "1",
        "X-Signature": sig,
    }


def ensure_admin_user(app):
    with app.app_context():
        admin = User.query.filter_by(username="phase7_admin").first()
        if not admin:
            admin = User(username="phase7_admin", role=UserRole.INFRA_ADMIN)
            admin.set_password("adminpass")
            db.session.add(admin)
            db.session.commit()
    return {"Authorization": "Basic " + base64.b64encode(b"phase7_admin:adminpass").decode("ascii")}


# --------------------------------------------------------------------------
# Acceptance Tests (§66)
# --------------------------------------------------------------------------


def test_ip_change(client, app):
    """Spec §66 test: Device changes IP address -> IP_CHANGED event (LOW), remains ACTIVE."""
    dev_id, asset_id, key = create_asset_and_device(app)

    payload = {
        "inventory": {
            "hostname": "workstation-01",
            "ip_addresses": ["10.0.0.99"],  # Changed IP
            "mac_addresses": ["00:11:22:33:44:55"],
            "ram_total_mb": 16384,
            "gpus": ["NVIDIA RTX 3070"],
            "disks": ["Samsung 970 EVO 500GB"],
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        events = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.IP_CHANGED
        ).all()
        assert len(events) >= 1
        assert events[0].severity == EventSeverity.LOW
        # Asset link remains unchanged
        link = AssetDeviceLink.query.filter_by(
            device_id=dev.id, relationship_status=RelationshipStatus.ACTIVE
        ).first()
        assert link is not None
        assert link.asset.asset_id == asset_id


def test_hostname_change(client, app):
    """Spec §66 test: Hostname changes -> HOSTNAME_CHANGED event (LOW), remains ACTIVE."""
    dev_id, _asset_id, key = create_asset_and_device(app)

    payload = {
        "inventory": {
            "hostname": "workstation-renamed",
            "ip_addresses": ["10.0.0.50"],
            "mac_addresses": ["00:11:22:33:44:55"],
            "ram_total_mb": 16384,
            "gpus": ["NVIDIA RTX 3070"],
            "disks": ["Samsung 970 EVO 500GB"],
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        events = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.HOSTNAME_CHANGED
        ).all()
        assert len(events) >= 1
        assert events[0].severity == EventSeverity.LOW


def test_gpu_upgrade(client, app):
    """Spec §66 test: GPU upgraded -> GPU_CHANGED event (LOW), remains ACTIVE."""
    dev_id, _, key = create_asset_and_device(app)

    payload = {
        "inventory": {
            "hostname": "workstation-01",
            "ip_addresses": ["10.0.0.50"],
            "gpus": ["NVIDIA RTX 4090"],  # Upgraded GPU
            "disks": ["Samsung 970 EVO 500GB"],
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        events = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.GPU_CHANGED
        ).all()
        assert len(events) >= 1
        assert events[0].severity == EventSeverity.LOW


def test_ssd_replacement(client, app):
    """Spec §66 test: Disk/SSD replaced -> DISK_CHANGED event (MEDIUM), remains ACTIVE."""
    dev_id, _, key = create_asset_and_device(app)

    payload = {
        "inventory": {
            "hostname": "workstation-01",
            "ip_addresses": ["10.0.0.50"],
            "disks": ["Crucial T700 2TB"],  # Replaced disk
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        events = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.DISK_CHANGED
        ).all()
        assert len(events) >= 1
        assert events[0].severity == EventSeverity.MEDIUM


def test_os_reinstall(client, app):
    """Spec §66 test: OS reinstalled on same hardware -> decision engine identifies candidate, PENDING_REVERIFICATION."""
    dev_id, _, _ = create_asset_and_device(
        app, mb_serial="MB-REINSTALL-1", uuid_str="UUID-REINSTALL-1"
    )

    with app.app_context():
        obs = Observation(
            evidence={
                "machine_uuid_hash": "UUID-REINSTALL-1",
                "motherboard_serial_hash": "MB-REINSTALL-1",
                "bios_serial_hash": "BIOS-111",
                "cpu_signature": "Intel i7",
            },
            signature_valid=False,
            valid_signature_for_active_device=False,
        )

        decision, candidates, score = determine_device_identity(obs)
        assert decision == IdentityDecision.PENDING_REVERIFICATION
        assert len(candidates) == 1
        assert candidates[0].device_id == dev_id
        assert score > 80.0


def test_identical_machine(client, app):
    """Spec §66 test: Two identical spec machines with different tokens map to separate assets/devices."""
    with app.app_context():
        asset1 = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TAG-LAB-01",
            asset_type=AssetType.DESKTOP,
        )
        asset2 = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TAG-LAB-02",
            asset_type=AssetType.DESKTOP,
        )
        db.session.add_all([asset1, asset2])
        db.session.commit()

        raw_tok1, _ = create_token_for_asset(asset1.id, "admin")
        raw_tok2, _ = create_token_for_asset(asset2.id, "admin")
        db.session.commit()

    # Enroll Machine 1
    k1 = Ed25519PrivateKey.generate()
    pub1 = base64.b64encode(
        k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    nonce1 = uuid.uuid4().hex
    ts1 = int(time.time())
    h1 = hashlib.sha256(raw_tok1.encode()).hexdigest()
    sig1 = base64.b64encode(k1.sign(f"enroll\n{h1}\n{ts1}\n{nonce1}".encode())).decode()

    p1 = {
        "enrollment_token": raw_tok1,
        "device_public_key": pub1,
        "proof_of_possession": sig1,
        "timestamp": ts1,
        "nonce": nonce1,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-M1",
            "motherboard_serial_hash": "MB-M1",
            "cpu_signature": "Ryzen 9",
        },
        "inventory": {"hostname": "lab-pc-01", "cpu_model": "Ryzen 9", "ram_total_mb": 32768},
    }
    resp1 = client.post("/api/v1/agents/enroll", json=p1)
    assert resp1.status_code == 200, resp1.get_json()
    res1_data = resp1.get_json()

    # Enroll Machine 2 (Identical hardware specs, different UUID/serial)
    k2 = Ed25519PrivateKey.generate()
    pub2 = base64.b64encode(
        k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    nonce2 = uuid.uuid4().hex
    ts2 = int(time.time())
    h2 = hashlib.sha256(raw_tok2.encode()).hexdigest()
    sig2 = base64.b64encode(k2.sign(f"enroll\n{h2}\n{ts2}\n{nonce2}".encode())).decode()

    p2 = {
        "enrollment_token": raw_tok2,
        "device_public_key": pub2,
        "proof_of_possession": sig2,
        "timestamp": ts2,
        "nonce": nonce2,
        "identity_evidence": {
            "machine_uuid_hash": "UUID-M2",
            "motherboard_serial_hash": "MB-M2",
            "cpu_signature": "Ryzen 9",
        },
        "inventory": {"hostname": "lab-pc-02", "cpu_model": "Ryzen 9", "ram_total_mb": 32768},
    }
    resp2 = client.post("/api/v1/agents/enroll", json=p2)
    assert resp2.status_code == 200
    res2_data = resp2.get_json()

    assert res1_data["device_id"] != res2_data["device_id"]
    assert res1_data["asset_id"] != res2_data["asset_id"]


def test_duplicate_credential(client, app):
    """Spec §66 test: Heartbeat with unexpected agent_instance_id -> SUSPENDED + DUPLICATE_DEVICE_IDENTITY."""
    dev_id, _, key = create_asset_and_device(app)

    # Send heartbeat with unexpected agent_instance_id within active window
    payload = {
        "device_id": dev_id,
        "timestamp": int(time.time()),
        "agent_instance_id": "rogue-cloned-instance-999",
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "device_suspended"

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.SUSPENDED
        event = DeviceEvent.query.filter_by(
            device_id=dev.id,
            event_type=DeviceEventType.DUPLICATE_DEVICE_IDENTITY,
        ).first()
        assert event is not None
        assert event.severity == EventSeverity.CRITICAL


def test_motherboard_replacement(client, app):
    """Spec §66 test: Motherboard replaced (≥2 strong anchors changed) -> PENDING_REVERIFICATION, approved by admin."""
    dev_id, _, key = create_asset_and_device(app, mb_serial="MB-ORIG", uuid_str="UUID-ORIG")

    # Send updated identity evidence with changed motherboard and UUID
    payload = {
        "identity_evidence": {
            "motherboard_serial_hash": "MB-REPLACED-NEW",
            "machine_uuid_hash": "UUID-NEW-CHASSIS",
            "bios_serial_hash": "BIOS-111",
            "cpu_signature": "Intel i7",
            "fingerprint": "fp-replaced-mb",
            "fingerprint_version": 1,
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/identity", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/identity", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.PENDING_REVERIFICATION
        events = DeviceEvent.query.filter_by(device_id=dev.id).all()
        types = [e.event_type for e in events]
        assert DeviceEventType.MOTHERBOARD_CHANGED in types
        assert DeviceEventType.IDENTITY_CHANGE_DETECTED in types

    # Admin approves hardware change
    admin_headers = ensure_admin_user(app)
    appr_resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/approve-hardware-change", headers=admin_headers
    )
    assert appr_resp.status_code == 200
    assert appr_resp.get_json()["status"] == "approved"

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        latest_ev = (
            DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .first()
        )
        assert latest_ev.trusted is True


def test_dual_boot_two_os_one_device(client, app):
    """Spec §66 test: Dual-boot modeled as one PhysicalDevice + multiple OSInstallation rows."""
    dev_id, _, key = create_asset_and_device(app)

    # Second OS (Windows) observed on same device
    payload = {
        "inventory": {"hostname": "workstation-01", "ip_addresses": ["10.0.0.50"]},
        "os": {
            "family": "WINDOWS",
            "name": "Windows 11 Pro",
            "version": "23H2",
            "architecture": "x86_64",
            "os_machine_id_hash": "windows-guid-hash-99",
        },
        "agent_instance_id": "inst-win-02",
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        # Exactly one physical device
        assert dev is not None
        # Multiple OSInstallation rows
        os_list = OSInstallation.query.filter_by(device_id=dev.id).all()
        assert len(os_list) == 2
        fams = {os_i.os_family for os_i in os_list}
        assert OsFamily.LINUX in fams
        assert OsFamily.WINDOWS in fams


def test_ram_upgrade(client, app):
    """Spec §66 test: RAM upgraded -> RAM_CHANGED event (LOW), remains ACTIVE."""
    dev_id, _, key = create_asset_and_device(app)

    payload = {
        "inventory": {
            "hostname": "workstation-01",
            "ram_total_mb": 65536,  # Upgraded to 64GB
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body, headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE
        events = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.RAM_CHANGED
        ).all()
        assert len(events) >= 1
        assert events[0].severity == EventSeverity.LOW


def test_score_never_links_asset(app):
    """Spec §66 test: High similarity score never creates an AssetDeviceLink on its own."""
    create_asset_and_device(app, mb_serial="MB-SCORE-TEST", uuid_str="UUID-SCORE-TEST")

    with app.app_context():
        initial_links_count = AssetDeviceLink.query.count()

        # Observation with 100% matching hardware from unenrolled source without token
        obs = Observation(
            evidence={
                "machine_uuid_hash": "UUID-SCORE-TEST",
                "motherboard_serial_hash": "MB-SCORE-TEST",
                "bios_serial_hash": "BIOS-111",
                "cpu_signature": "Intel i7",
                "disk_identity_hash": "DISK-PRIMARY",
                "network_identity_hash": "MAC-ETH0",
            },
            signature_valid=False,
            valid_signature_for_active_device=False,
        )

        decision, _candidates, score = determine_device_identity(obs)
        assert score >= 99.0
        # Decision must route to re-verification or manual verification, NEVER link
        assert decision in (
            IdentityDecision.PENDING_REVERIFICATION,
            IdentityDecision.MANUAL_VERIFICATION,
        )

        # AssetDeviceLink count must NOT have increased
        after_links_count = AssetDeviceLink.query.count()
        assert after_links_count == initial_links_count


def test_golden_image_clones_are_distinct(tmp_path):
    """Spec §66 test: Cloned golden image endpoints generate unique keys and instance IDs on first boot."""
    from agent.identity.device_id import IdentityStore
    from agent.identity.keys import FileKeyStore, load_or_create_key
    from agent.storage.database import AgentDatabase

    # Endpoint 1 boots from blank state
    dir1 = tmp_path / "endpoint1"
    dir1.mkdir()
    db1 = AgentDatabase(dir1 / "state.db")
    store1 = IdentityStore(db1)
    keystore1 = FileKeyStore(dir1 / "device.key")
    key1 = load_or_create_key(keystore1)

    # Endpoint 2 boots from identical blank master state
    dir2 = tmp_path / "endpoint2"
    dir2.mkdir()
    db2 = AgentDatabase(dir2 / "state.db")
    store2 = IdentityStore(db2)
    keystore2 = FileKeyStore(dir2 / "device.key")
    key2 = load_or_create_key(keystore2)

    # Unique private keys and agent_instance_ids
    assert store1.agent_instance_id != store2.agent_instance_id

    raw_k1 = key1.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    raw_k2 = key2.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert raw_k1 != raw_k2


# --------------------------------------------------------------------------
# Additional unit tests for identity_service coverage
# --------------------------------------------------------------------------


def test_similarity_score_calculation():
    """Unit test for calculate_similarity_score weighting and missing field normalization."""
    ev_a = {"machine_uuid_hash": "u1", "motherboard_serial_hash": "mb1", "cpu_signature": "cpu1"}
    ev_b = {"machine_uuid_hash": "u1", "motherboard_serial_hash": "mb1", "cpu_signature": "cpu1"}
    assert calculate_similarity_score(ev_a, ev_b) == 100.0

    # Partial match
    ev_c = {"machine_uuid_hash": "u1", "motherboard_serial_hash": "different"}
    score = calculate_similarity_score(ev_a, ev_c)
    assert 0.0 < score < 100.0

    # Empty inputs
    assert calculate_similarity_score({}, {}) == 0.0


def test_admin_unclaimed_and_pair_endpoints(client, app):
    """Test GET /unclaimed and POST /pair admin workflows."""
    admin_headers = ensure_admin_user(app)
    now = datetime.now(UTC)

    with app.app_context():
        # Create an unclaimed device
        dev = PhysicalDevice(
            device_id=generate_device_id(),
            device_public_key="test-key",
            status=DeviceStatus.UNCLAIMED,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(dev)

        # Create an asset
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TAG-PAIR-TEST",
            asset_type=AssetType.DESKTOP,
        )
        db.session.add(asset)
        db.session.commit()
        dev_id = dev.device_id
        asset_id = asset.asset_id

    # List unclaimed
    resp = client.get("/api/v1/admin/devices/unclaimed", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(d["device_id"] == dev_id for d in data["devices"])

    # Pair device to asset
    pair_resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/pair",
        json={"asset_id": asset_id},
        headers=admin_headers,
    )
    assert pair_resp.status_code == 200
    assert pair_resp.get_json()["status"] == "paired"

    with app.app_context():
        d = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert d.status == DeviceStatus.PENDING_VERIFICATION
        link = AssetDeviceLink.query.filter_by(device_id=d.id).first()
        assert link is not None
        assert link.relationship_status == RelationshipStatus.ACTIVE


def test_decision_engine_branches(app):
    """Test decision engine branches: valid signature, unknown, manual verification, ambiguous."""
    with app.app_context():
        dev_id, _, _ = create_asset_and_device(
            app, mb_serial="MB-BRANCH-1", uuid_str="UUID-BRANCH-1"
        )

        # 1. Valid signature for active device -> SAME_DEVICE
        obs_sig = Observation(
            device_id=dev_id,
            valid_signature_for_active_device=True,
        )
        dec, cands, score = determine_device_identity(obs_sig)
        assert dec == IdentityDecision.SAME_DEVICE
        assert len(cands) == 1
        assert score == 100.0

        # 2. Unknown device (no candidates match) -> UNKNOWN_DEVICE
        obs_unk = Observation(evidence={"machine_uuid_hash": "non-existent-uuid"})
        dec, cands, score = determine_device_identity(obs_unk)
        assert dec == IdentityDecision.UNKNOWN_DEVICE
        assert len(cands) == 0

        # 3. Only 1 strong anchor matches -> MANUAL_VERIFICATION
        obs_manual = Observation(
            evidence={
                "machine_uuid_hash": "UUID-BRANCH-1",
                "motherboard_serial_hash": "different-mb",
            }
        )
        dec, cands, score = determine_device_identity(obs_manual)
        assert dec == IdentityDecision.MANUAL_VERIFICATION
        assert len(cands) == 1


def test_reconcile_tpm_and_nic_changed(client, app):
    """Test TPM_CHANGED and NIC_CHANGED event generation."""
    dev_id, _, key = create_asset_and_device(app)

    # 1. NIC change
    payload_inv = {
        "inventory": {
            "hostname": "workstation-01",
            "mac_addresses": ["00:aa:bb:cc:dd:ee"],
        }
    }
    body_inv = json.dumps(payload_inv).encode("utf-8")
    headers_inv = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body_inv)
    headers_inv["Content-Type"] = "application/json"
    resp_inv = client.post("/api/v1/agents/inventory", data=body_inv, headers=headers_inv)
    assert resp_inv.status_code == 200

    # 2. TPM change
    payload_id = {
        "identity_evidence": {
            "machine_uuid_hash": "UUID-ORIG-5678",
            "motherboard_serial_hash": "MB-ORIG-1234",
            "tpm_identity": "TPM-NEW-VERSION-2",
        }
    }
    body_id = json.dumps(payload_id).encode("utf-8")
    headers_id = sign_req(dev_id, key, "POST", "/api/v1/agents/identity", body_id)
    headers_id["Content-Type"] = "application/json"
    resp_id = client.post("/api/v1/agents/identity", data=body_id, headers=headers_id)
    assert resp_id.status_code == 200

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        nic_ev = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.NIC_CHANGED
        ).first()
        assert nic_ev is not None
        assert nic_ev.severity == EventSeverity.MEDIUM

        tpm_ev = DeviceEvent.query.filter_by(
            device_id=dev.id, event_type=DeviceEventType.TPM_CHANGED
        ).first()
        assert tpm_ev is not None
        assert tpm_ev.severity == EventSeverity.HIGH


def test_identity_service_error_handling(app):
    """Test error handling in approve_hardware_change and pair_unclaimed_device."""
    from app.services.identity_service import approve_hardware_change, pair_unclaimed_device

    with app.app_context():
        with pytest.raises(ValueError, match="not found"):
            approve_hardware_change("VD-DEVICE-NONEXISTENT", "admin")

        with pytest.raises(ValueError, match="not found"):
            pair_unclaimed_device("VD-DEVICE-NONEXISTENT", "VD-ASSET-000001", "admin")
