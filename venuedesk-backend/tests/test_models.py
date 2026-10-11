"""Unit tests for database models, constraints, and seed CLI."""
from datetime import UTC

import pytest
from sqlalchemy.exc import IntegrityError

from app.cli import seed_demo_command
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    DeviceStatus,
    PhysicalDevice,
    RelationshipStatus,
    RequestNonce,
    User,
    UserRole,
    generate_device_id,
    generate_next_asset_id,
)


def test_asset_id_generation_sequential(app):
    """Verify that asset IDs are sequential and zero-padded 6 digits."""
    with app.app_context():
        id1 = generate_next_asset_id(db.session)
        id2 = generate_next_asset_id(db.session)
        id3 = generate_next_asset_id(db.session)

        assert id1 == "VD-ASSET-000001"
        assert id2 == "VD-ASSET-000002"
        assert id3 == "VD-ASSET-000003"


def test_asset_creation(app):
    """Verify asset insertion with required and optional fields."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="TEST-TAG-01",
            asset_type=AssetType.DESKTOP,
            department_id="DEP_CS",
            room_id="ROOM_101",
            lifecycle_status=AssetLifecycleStatus.DRAFT
        )
        db.session.add(asset)
        db.session.commit()

        retrieved = Asset.query.filter_by(asset_tag="TEST-TAG-01").first()
        assert retrieved is not None
        assert retrieved.asset_id == "VD-ASSET-000001"
        assert retrieved.lifecycle_status == AssetLifecycleStatus.DRAFT


def test_physical_device_and_link(app):
    """Verify physical device creation and active link establishment."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="ASSET-PC-01"
        )
        device = PhysicalDevice(
            device_id=generate_device_id(),
            device_public_key="base64-fake-pubkey",
            status=DeviceStatus.ENROLLING
        )
        db.session.add_all([asset, device])
        db.session.commit()

        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=device.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_by="admin"
        )
        db.session.add(link)
        db.session.commit()

        assert link.id is not None
        assert link.relationship_status == RelationshipStatus.ACTIVE


def test_single_active_link_constraint_on_asset(app):
    """Enforce invariant: an asset cannot have two ACTIVE device links."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-PC-02")
        dev1 = PhysicalDevice(device_id=generate_device_id(), device_public_key="pubkey1")
        dev2 = PhysicalDevice(device_id=generate_device_id(), device_public_key="pubkey2")
        db.session.add_all([asset, dev1, dev2])
        db.session.commit()

        link1 = AssetDeviceLink(asset_id=asset.id, device_id=dev1.id, relationship_status=RelationshipStatus.ACTIVE)
        db.session.add(link1)
        db.session.commit()

        # Attempt second active link for the same asset
        link2 = AssetDeviceLink(asset_id=asset.id, device_id=dev2.id, relationship_status=RelationshipStatus.ACTIVE)
        db.session.add(link2)
        with pytest.raises(ValueError, match="already has an ACTIVE link"):
            db.session.commit()
        db.session.rollback()


def test_single_active_link_constraint_on_device(app):
    """Enforce invariant: a device cannot have two ACTIVE asset links."""
    with app.app_context():
        asset1 = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-PC-03")
        asset2 = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-PC-04")
        dev = PhysicalDevice(device_id=generate_device_id(), device_public_key="pubkey3")
        db.session.add_all([asset1, asset2, dev])
        db.session.commit()

        link1 = AssetDeviceLink(asset_id=asset1.id, device_id=dev.id, relationship_status=RelationshipStatus.ACTIVE)
        db.session.add(link1)
        db.session.commit()

        # Attempt second active link for the same device
        link2 = AssetDeviceLink(asset_id=asset2.id, device_id=dev.id, relationship_status=RelationshipStatus.ACTIVE)
        db.session.add(link2)
        with pytest.raises(ValueError, match="already has an ACTIVE link"):
            db.session.commit()
        db.session.rollback()


def test_request_nonce_uniqueness(app):
    """Enforce unique (device_id, nonce) constraint."""
    with app.app_context():
        from datetime import datetime, timedelta
        expires = datetime.now(UTC) + timedelta(minutes=5)
        n1 = RequestNonce(device_id="VD-DEVICE-11112222", nonce="unique-nonce-1", expires_at=expires)
        db.session.add(n1)
        db.session.commit()

        n2 = RequestNonce(device_id="VD-DEVICE-11112222", nonce="unique-nonce-1", expires_at=expires)
        db.session.add(n2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_seed_demo_command(app):
    """Verify seed-demo CLI populates demo assets and admin user."""
    runner = app.test_cli_runner()
    result = runner.invoke(seed_demo_command)
    assert result.exit_code == 0
    assert "Seed demo completed successfully." in result.output

    with app.app_context():
        ai_pc = Asset.query.filter_by(asset_tag="AI-LAB-PC-07").first()
        cse_pc = Asset.query.filter_by(asset_tag="CSE-LAB-PC-12").first()
        admin = User.query.filter_by(username="admin").first()

        assert ai_pc is not None
        assert cse_pc is not None
        assert admin is not None
        assert admin.role == UserRole.INFRA_ADMIN
        assert admin.check_password("admin123") is True
