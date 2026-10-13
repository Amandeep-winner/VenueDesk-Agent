"""Tests verifying immutable append-only audit log guards and state action auditing."""

import base64
from datetime import UTC, datetime

import pytest
from app import create_app
from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AssetLifecycleStatus,
    AssetType,
    AuditAction,
    AuditLog,
    DeviceStatus,
    PhysicalDevice,
    generate_next_asset_id,
)
from app.services.identity_service import pair_device
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def app():
    app_instance = create_app("testing")
    with app_instance.app_context():
        db.create_all()
        yield app_instance
        db.session.remove()
        db.drop_all()


def test_audit_log_update_raises_guard(app):
    """Enforce append-only invariant: attempting to UPDATE an AuditLog raises PermissionError."""
    with app.app_context():
        log = AuditLog(
            actor_id="admin_user",
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_ENROLLED,
            entity_type="device",
            entity_id="VD-DEVICE-TEST01",
            new_value={"status": "ACTIVE"},
        )
        db.session.add(log)
        db.session.commit()

        # Attempting to modify audit record must fail
        log.entity_id = "VD-DEVICE-MODIFIED"
        with pytest.raises(
            PermissionError, match="strictly append-only and cannot be updated"
        ):
            db.session.commit()
        db.session.rollback()


def test_audit_log_delete_raises_guard(app):
    """Enforce append-only invariant: attempting to DELETE an AuditLog raises PermissionError."""
    with app.app_context():
        log = AuditLog(
            actor_id="admin_user",
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_ENROLLED,
            entity_type="device",
            entity_id="VD-DEVICE-TEST02",
            new_value={"status": "ACTIVE"},
        )
        db.session.add(log)
        db.session.commit()

        # Attempting to delete audit record must fail
        db.session.delete(log)
        with pytest.raises(
            PermissionError, match="strictly append-only and cannot be deleted"
        ):
            db.session.commit()
        db.session.rollback()


def test_state_changing_pairing_produces_audit_row(app):
    """Every state-changing administrative action produces exactly one audit row."""
    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="ASSET-AUDIT-01",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

        dev = PhysicalDevice(
            device_id="VD-DEVICE-AUDIT01",
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.UNCLAIMED,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db.session.add(dev)
        db.session.commit()

        initial_audits = AuditLog.query.count()

        # Pair device
        pair_device(dev.id, asset.id, admin_name="compliance_officer")

        final_audits = AuditLog.query.count()
        assert final_audits == initial_audits + 1

        last_audit = AuditLog.query.order_by(AuditLog.id.desc()).first()
        assert last_audit.actor_id == "compliance_officer"
        assert last_audit.action == AuditAction.DEVICE_LINKED
        assert last_audit.entity_type == "link"
        assert last_audit.new_value["device_id"] == dev.device_id
        assert last_audit.new_value["asset_id"] == asset.asset_id
