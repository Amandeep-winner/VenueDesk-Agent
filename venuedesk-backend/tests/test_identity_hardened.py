"""Comprehensive hardened identity reconciliation test suite for Phase 3.

Covers fingerprint versioning, tri-state missing evidence handling,
change classification, historical evidence preservation, and golden vector pinning.
"""

import base64
import json
from datetime import UTC, datetime

from agent.identity.fingerprint import (
    FieldMatchResult,
    compare_field,
    fingerprint,
    norm,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_authenticated_communication import sign_request

from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EvidenceSource,
    HardwareChangeRecord,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    generate_device_id,
    generate_next_asset_id,
)
from app.services.identity_service import (
    IdentityDecision,
    Observation,
    approve_hardware_change,
    calculate_similarity_score,
    determine_device_identity,
    reconcile_device_evidence,
    reconcile_device_inventory,
)


def _setup_enrolled_device_with_inventory(
    app,
    hostname="lab-01",
    mb_serial="MB-1001",
    uuid_str="4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
    bios_serial="BIOS-1001",
    ram_mb=16384,
    gpus=None,
    disks=None,
    ips=None,
):
    """Helper creating asset, device, active link, trusted evidence, and inventory."""
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
            linked_by="admin",
        )
        db.session.add(link)

        evidence = DeviceIdentityEvidence(
            device_id=device.id,
            machine_uuid_hash=uuid_str,
            motherboard_serial_hash=mb_serial,
            bios_serial_hash=bios_serial,
            cpu_signature="Intel Core i7",
            gpu_signature="NVIDIA RTX 3080",
            disk_identity_hash="DISK-NVME-1",
            network_identity_hash="MAC-ETH0",
            tpm_identity="TPM-CHIP-1",
            fingerprint="fp-initial-v1",
            fingerprint_version=1,
            captured_at=now,
            trusted=True,
        )
        db.session.add(evidence)

        inv = DeviceInventory(
            device_id=device.id,
            hostname=hostname,
            ip_addresses=ips or ["192.168.1.100"],
            mac_addresses=["00:11:22:33:44:55"],
            cpu_model="Intel Core i7-12700K",
            cpu_cores=12,
            ram_total_mb=ram_mb,
            gpus=gpus or ["NVIDIA RTX 3080"],
            disks=disks or ["Samsung SSD 980"],
            os_summary="Ubuntu 24.04",
            bios_version="1.0.0",
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
            os_machine_id_hash="mid-hash-linux-1",
            agent_instance_id="inst-1",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)
        db.session.commit()
        device_pk = device.id

    return dev_id, device_pk, key


def test_ip_change(app):
    """IP address change updates inventory, emits IP_CHANGED (LOW), and requires no approval."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, ips=["192.168.1.100"])

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        new_inv = {"ip_addresses": ["192.168.1.200", "10.0.0.50"]}
        events = reconcile_device_inventory(device, new_inv)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.IP_CHANGED in event_types

        # Assert change record created with requires_approval=False
        records = HardwareChangeRecord.query.filter_by(
            device_id=device.id, field="ip_addresses"
        ).all()
        assert len(records) >= 1
        assert not records[0].requires_approval
        assert records[0].evidence_source == EvidenceSource.AGENT_INVENTORY
        assert device.status == DeviceStatus.ACTIVE


def test_hostname_change(app):
    """Hostname change updates inventory, emits HOSTNAME_CHANGED (LOW), and requires no approval."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, hostname="lab-old")

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        new_inv = {"hostname": "lab-new"}
        events = reconcile_device_inventory(device, new_inv)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.HOSTNAME_CHANGED in event_types

        records = HardwareChangeRecord.query.filter_by(device_id=device.id, field="hostname").all()
        assert len(records) >= 1
        assert not records[0].requires_approval
        assert device.status == DeviceStatus.ACTIVE


def test_ram_change(app):
    """RAM change emits HARDWARE_CHANGED and RAM_CHANGED (LOW), requiring no approval."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, ram_mb=16384)

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        new_inv = {"ram_total_mb": 32768}
        events = reconcile_device_inventory(device, new_inv)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.RAM_CHANGED in event_types
        assert DeviceEventType.HARDWARE_CHANGED in event_types

        records = HardwareChangeRecord.query.filter_by(
            device_id=device.id, field="ram_total_mb"
        ).all()
        assert len(records) >= 1
        assert not records[0].requires_approval
        assert device.status == DeviceStatus.ACTIVE


def test_gpu_change(app):
    """GPU change emits HARDWARE_CHANGED and GPU_CHANGED (LOW), requiring no approval."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, gpus=["NVIDIA RTX 3070"])

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        new_inv = {"gpus": ["NVIDIA RTX 4090"]}
        events = reconcile_device_inventory(device, new_inv)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.GPU_CHANGED in event_types
        assert DeviceEventType.HARDWARE_CHANGED in event_types

        records = HardwareChangeRecord.query.filter_by(device_id=device.id, field="gpus").all()
        assert len(records) >= 1
        assert not records[0].requires_approval
        assert device.status == DeviceStatus.ACTIVE


def test_disk_replacement(app):
    """Disk change emits DISK_CHANGED (MEDIUM) and requires no approval."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, disks=["Samsung 970"])

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        new_inv = {"disks": ["Samsung 990 PRO"]}
        events = reconcile_device_inventory(device, new_inv)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.DISK_CHANGED in event_types

        records = HardwareChangeRecord.query.filter_by(device_id=device.id, field="disks").all()
        assert len(records) >= 1
        assert not records[0].requires_approval
        assert device.status == DeviceStatus.ACTIVE


def test_motherboard_evidence_change_alone_requires_review(app):
    """Motherboard serial change alone requires admin approval and enters PENDING_REVERIFICATION."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app, mb_serial="MB-INITIAL")

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        # Motherboard changed, other strong anchors remain the same
        new_ev = {
            "machine_uuid_hash": "4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
            "bios_serial_hash": "BIOS-1001",
            "motherboard_serial_hash": "MB-REPLACED-DIFFERENT",
            "tpm_identity": "TPM-CHIP-1",
        }
        events = reconcile_device_evidence(device, new_ev)

        event_types = [e.event_type for e in events]
        assert DeviceEventType.MOTHERBOARD_CHANGED in event_types

        # Must require approval and place device in PENDING_REVERIFICATION
        records = HardwareChangeRecord.query.filter_by(
            device_id=device.id, field="motherboard_serial_hash"
        ).all()
        assert len(records) >= 1
        assert records[0].requires_approval
        assert device.status == DeviceStatus.PENDING_REVERIFICATION

        # Admin approves the change
        approve_hardware_change(device.id, admin_name="admin_alice")
        assert device.status == DeviceStatus.ACTIVE
        assert records[0].approved_by == "admin_alice"
        assert records[0].approved_at is not None


def test_missing_serial_never_equals_missing_serial():
    """Missing evidence (None == None) is UNKNOWN and never counts as a match."""
    # Test normalization of placeholders to None
    placeholders = [
        "",
        "none",
        "unknown",
        "null",
        "to be filled by o.e.m.",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff",
    ]
    for ph in placeholders:
        assert norm(ph) is None

    # compare_field tri-state
    assert compare_field(None, None) == FieldMatchResult.UNKNOWN
    assert compare_field("unknown", "unknown") == FieldMatchResult.UNKNOWN
    assert compare_field("none", "none") == FieldMatchResult.UNKNOWN
    assert compare_field("ABC-123", "ABC-123") == FieldMatchResult.MATCH
    assert compare_field("ABC-123", "XYZ-999") == FieldMatchResult.MISMATCH

    # Similarity score between two empty/placeholder machines must be 0.0
    ev_empty_1 = {"machine_uuid": "unknown", "bios_serial": "", "motherboard_serial": "none"}
    ev_empty_2 = {"machine_uuid": "none", "bios_serial": None, "motherboard_serial": "unknown"}
    assert calculate_similarity_score(ev_empty_1, ev_empty_2) == 0.0


def test_fingerprint_unchanged_for_released_version():
    """Golden-vector test: fixed input pins exact fingerprint v1 hash."""
    fixed_evidence = {
        "machine_uuid": "4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
        "bios_serial": "BIOS-TEST-1234",
        "motherboard_serial": "MB-TEST-5678",
        "cpu": "Intel Core i7-12700K",
        "gpus": ["NVIDIA GeForce RTX 3080"],
        "disks": ["Samsung SSD 980 PRO 1TB"],
        "nics": ["eth0", "docker0"],
    }
    # Expected golden SHA-256 hash for version 1
    expected_v1 = "c6a7bb63474300735b79d1caac1d79a39d746d98e0e66a9fccefe56cc1403da8"
    assert fingerprint(fixed_evidence, version=1) == expected_v1


def test_fingerprint_version_migration_preserves_identity(app):
    """Fingerprint version upgrade preserves device identity and emits FINGERPRINT_MIGRATED."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app)

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        # Agent reports fingerprint_version=2 with new hash
        new_ev = {
            "machine_uuid_hash": "4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
            "motherboard_serial_hash": "MB-1001",
            "bios_serial_hash": "BIOS-1001",
            "tpm_identity": "TPM-CHIP-1",
            "fingerprint": "fp-new-v2-hash",
            "fingerprint_version": 2,
        }
        events = reconcile_device_evidence(device, new_ev)
        event_types = [e.event_type for e in events]
        assert DeviceEventType.FINGERPRINT_MIGRATED in event_types
        assert device.status == DeviceStatus.ACTIVE


def test_conflicting_strong_evidence_enters_pending_reverification(app):
    """Conflict in >= 2 strong anchors enters PENDING_REVERIFICATION and emits IDENTITY_CHANGE_DETECTED."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app)

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)
        # Both motherboard and UUID conflict
        conflicting_ev = {
            "machine_uuid_hash": "UUID-NEW-CONFLICTING",
            "motherboard_serial_hash": "MB-NEW-CONFLICTING",
            "bios_serial_hash": "BIOS-1001",
            "tpm_identity": "TPM-CHIP-1",
        }
        events = reconcile_device_evidence(device, conflicting_ev)
        event_types = [e.event_type for e in events]
        assert DeviceEventType.IDENTITY_CHANGE_DETECTED in event_types
        assert device.status == DeviceStatus.PENDING_REVERIFICATION

        record = HardwareChangeRecord.query.filter_by(
            device_id=device.id, field="strong_anchors_conflict"
        ).first()
        assert record is not None
        assert record.requires_approval


def test_identical_hardware_new_machine_not_auto_paired(app):
    """A new machine with identical hardware but no token/credential is never automatically paired."""
    _dev_id, _dev_pk, _ = _setup_enrolled_device_with_inventory(app)

    with app.app_context():
        # New unauthenticated observation with identical specs
        obs = Observation(
            device_id=None,
            device_public_key="new-key-b64",
            signature_valid=False,
            valid_signature_for_active_device=False,
            evidence={
                "machine_uuid_hash": "4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
                "motherboard_serial_hash": "MB-1001",
                "bios_serial_hash": "BIOS-1001",
                "tpm_identity": "TPM-CHIP-1",
            },
        )
        decision, _candidates, _score = determine_device_identity(obs)
        # Never automatically paired as SAME_DEVICE without credentials
        assert decision != IdentityDecision.SAME_DEVICE
        assert decision in (
            IdentityDecision.PENDING_REVERIFICATION,
            IdentityDecision.MANUAL_VERIFICATION,
        )


def test_similarity_score_never_links_asset(app):
    """Assert security invariant: high similarity score NEVER creates or alters an AssetDeviceLink."""
    with app.app_context():
        initial_links_count = AssetDeviceLink.query.count()

        # Observation with 100% score but unauthenticated
        obs = Observation(
            device_id=None,
            device_public_key="some-key",
            signature_valid=False,
            valid_signature_for_active_device=False,
            evidence={
                "machine_uuid_hash": "4A2E7092-225C-4F43-B5DF-DE29E404EBE1",
                "motherboard_serial_hash": "MB-1001",
            },
        )
        determine_device_identity(obs)

        # Confirm database links are untouched
        assert AssetDeviceLink.query.count() == initial_links_count


def test_history_retained_after_each_change(app):
    """Multiple sequential changes preserve complete history in hardware_change_records append-only."""
    _dev_id, dev_pk, _ = _setup_enrolled_device_with_inventory(app)

    with app.app_context():
        device = db.session.get(PhysicalDevice, dev_pk)

        # Change 1: IP
        reconcile_device_inventory(device, {"ip_addresses": ["10.0.0.1"]})
        # Change 2: RAM
        reconcile_device_inventory(device, {"ram_total_mb": 65536})
        # Change 3: Disk
        reconcile_device_inventory(device, {"disks": ["Micron 2TB NVMe"]})

        records = (
            HardwareChangeRecord.query.filter_by(device_id=device.id)
            .order_by(HardwareChangeRecord.occurred_at.asc())
            .all()
        )
        fields_recorded = [r.field for r in records]
        assert "ip_addresses" in fields_recorded
        assert "ram_total_mb" in fields_recorded
        assert "disks" in fields_recorded
        assert len(records) >= 3


def test_key_rotation_does_not_create_new_device(client, app):
    """Credential rotation increments credential_version without creating a new device or changing links."""
    dev_id, dev_pk, old_key = _setup_enrolled_device_with_inventory(app)

    # Generate new key
    new_key = Ed25519PrivateKey.generate()
    new_pub_raw = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b64 = base64.b64encode(new_pub_raw).decode("ascii")

    # Sign rotation payload with old key
    ts = int(datetime.now(UTC).timestamp())
    msg = f"rotate\n{dev_id}\n{new_pub_b64}\n{ts}".encode()
    sig_by_old = base64.b64encode(old_key.sign(msg)).decode("ascii")

    body = json.dumps(
        {
            "new_public_key": new_pub_b64,
            "signature_by_old_key": sig_by_old,
            "timestamp": ts,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    headers = sign_request(
        dev_id, old_key, "POST", "/api/v1/agents/rotate-credential", body, key_version=1
    )
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/rotate-credential", data=body, headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "rotated"
    assert resp.get_json()["credential_version"] == 2

    with app.app_context():
        # Assert no new PhysicalDevice was created
        assert PhysicalDevice.query.filter_by(device_id=dev_id).count() == 1
        device = db.session.get(PhysicalDevice, dev_pk)
        assert device.credential_version == 2
        assert device.device_public_key == new_pub_b64

        # Assert asset link is completely untouched
        active_links = AssetDeviceLink.query.filter_by(
            device_id=device.id, relationship_status=RelationshipStatus.ACTIVE
        ).count()
        assert active_links == 1
