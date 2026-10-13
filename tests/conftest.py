"""Shared test fixtures for the VenueDesk test suite."""
import base64
import uuid
from datetime import UTC, datetime

import pytest
from agent.storage.outbox import (
    PRIORITY_IDENTITY_EVENT,
    PRIORITY_INVENTORY,
    PRIORITY_TELEMETRY,
    Outbox,
)
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    DeviceStatus,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    generate_next_asset_id,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.fixtures.synthetic import (
    get_ai_lab_pc_07,
    get_cse_lab_pc_12,
    get_device_missing_serials,
    get_identical_hardware_pair,
)


@pytest.fixture
def ai_lab_pc_07():
    return get_ai_lab_pc_07()


@pytest.fixture
def cse_lab_pc_12():
    return get_cse_lab_pc_12()


@pytest.fixture
def identical_hardware_pair():
    return get_identical_hardware_pair()


@pytest.fixture
def device_missing_serials():
    return get_device_missing_serials()


@pytest.fixture
def dual_os_device(app):
    """Fixture providing a PhysicalDevice linked to an asset with two active OSInstallations."""
    with app.app_context():
        now = datetime.now(UTC)
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="ASSET-DUAL-FIX",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)
        db.session.flush()

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

        dev = PhysicalDevice(
            device_id=f"VD-DEVICE-{uuid.uuid4().hex[:8].upper()}",
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(dev)
        db.session.flush()

        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=dev.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_at=now,
        )
        db.session.add(link)

        os_win = OSInstallation(
            device_id=dev.id,
            os_installation_id="os-win-fix-01",
            os_family=OsFamily.WINDOWS,
            os_name="Windows 11",
            os_version="23H2",
            architecture="x86_64",
            os_machine_id_hash="hash-win-01",
            agent_instance_id="inst-win-fix",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        os_lin = OSInstallation(
            device_id=dev.id,
            os_installation_id="os-lin-fix-01",
            os_family=OsFamily.LINUX,
            os_name="Ubuntu",
            os_version="24.04",
            architecture="x86_64",
            os_machine_id_hash="hash-lin-01",
            agent_instance_id="inst-lin-fix",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_win)
        db.session.add(os_lin)
        db.session.commit()
        return dev.device_id, key


@pytest.fixture
def revoked_device(app):
    """Fixture providing a PhysicalDevice with REVOKED status."""
    with app.app_context():
        now = datetime.now(UTC)
        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

        dev = PhysicalDevice(
            device_id=f"VD-DEVICE-REVOKED-{uuid.uuid4().hex[:6].upper()}",
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.REVOKED,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(dev)
        db.session.commit()
        return dev.device_id, key


@pytest.fixture
def offline_agent_with_queue(tmp_path):
    """Fixture providing an Outbox populated with items of each priority level."""
    db_file = tmp_path / "offline_fixture_outbox.db"
    box = Outbox(db_file)
    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"event": "p0_evidence", "fingerprint": "fp_fix"})
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "fixture-host", "ram_total_mb": 16384})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample_id": 1, "cpu_percent": 12.5})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample_id": 2, "cpu_percent": 14.0})
    return box


@pytest.fixture
def fake_endpoint():
    """Factory helper providing real Ed25519 authenticated requests."""
    def _create_endpoint(device_id: str | None = None):
        key = Ed25519PrivateKey.generate()
        dev_id = device_id or f"VD-DEVICE-{uuid.uuid4().hex[:8].upper()}"
        return dev_id, key
    return _create_endpoint
