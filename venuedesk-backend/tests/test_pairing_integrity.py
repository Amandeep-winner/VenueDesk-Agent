"""Tests for device-to-asset mapping integrity, constraints, and race conditions."""
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    DeviceStatus,
    PhysicalDevice,
    RelationshipStatus,
    UserRole,
)
from app.services.identity_service import LinkConflictError, pair_device


def _create_asset(asset_id: str = "VD-ASSET-000100", tag: str = "TAG-001") -> Asset:
    asset = Asset(
        asset_id=asset_id,
        asset_tag=tag,
        lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
    )
    db.session.add(asset)
    db.session.flush()
    return asset


def _create_device(device_id: str = "VD-DEVICE-0001", status: DeviceStatus = DeviceStatus.UNCLAIMED) -> PhysicalDevice:
    dev = PhysicalDevice(
        device_id=device_id,
        device_public_key="test_public_key_b64",
        status=status,
    )
    db.session.add(dev)
    db.session.flush()
    return dev


def test_device_already_linked_cannot_link_to_second_asset(app):
    """A device with an active link cannot link to a second asset without reassignment."""
    with app.app_context():
        asset1 = _create_asset("VD-ASSET-000101", "TAG-101")
        asset2 = _create_asset("VD-ASSET-000102", "TAG-102")
        dev = _create_device("VD-DEVICE-0002", DeviceStatus.UNCLAIMED)
        db.session.commit()

        # First pairing succeeds
        pair_device(dev.device_id, asset1.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)

        # Second pairing must raise LinkConflictError
        with pytest.raises(LinkConflictError):
            pair_device(dev.device_id, asset2.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)


def test_asset_already_linked_cannot_accept_second_device(app):
    """An asset with an active link cannot accept a second device without reassignment."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000103", "TAG-103")
        dev1 = _create_device("VD-DEVICE-0003", DeviceStatus.UNCLAIMED)
        dev2 = _create_device("VD-DEVICE-0004", DeviceStatus.UNCLAIMED)
        db.session.commit()

        pair_device(dev1.device_id, asset.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)

        with pytest.raises(LinkConflictError):
            pair_device(dev2.device_id, asset.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)


def test_authorized_replacement_closes_old_link_and_preserves_history(app):
    """Authorized replacement with reassignment=True closes previous active link and creates a new one."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000104", "TAG-104")
        dev1 = _create_device("VD-DEVICE-0005", DeviceStatus.UNCLAIMED)
        dev2 = _create_device("VD-DEVICE-0006", DeviceStatus.UNCLAIMED)
        db.session.commit()

        pair_device(dev1.device_id, asset.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)

        # Now replace with dev2
        pair_device(
            dev2.device_id,
            asset.asset_id,
            admin_name="admin",
            actor_role=UserRole.INFRA_ADMIN,
            reassignment=True,
            reason="Computer replacement for lab upgrade",
        )

        links = AssetDeviceLink.query.filter_by(asset_id=asset.id).order_by(AssetDeviceLink.id.asc()).all()
        assert len(links) == 2
        # Old link is CLOSED
        assert links[0].device_id == dev1.id
        assert links[0].relationship_status == RelationshipStatus.CLOSED
        assert links[0].unlinked_at is not None
        assert links[0].reason == "Computer replacement for lab upgrade"

        # New link is ACTIVE
        assert links[1].device_id == dev2.id
        assert links[1].relationship_status == RelationshipStatus.ACTIVE


def test_unauthorized_reassignment_rejected(app):
    """Reassignment without infra_admin role or without reason is rejected."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000105", "TAG-105")
        dev1 = _create_device("VD-DEVICE-0007", DeviceStatus.UNCLAIMED)
        dev2 = _create_device("VD-DEVICE-0008", DeviceStatus.UNCLAIMED)
        db.session.commit()

        pair_device(dev1.device_id, asset.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)

        # Missing reason
        with pytest.raises(LinkConflictError):
            pair_device(
                dev2.device_id,
                asset.asset_id,
                admin_name="admin",
                actor_role=UserRole.INFRA_ADMIN,
                reassignment=True,
                reason="",  # empty reason
            )

        # Missing infra_admin role
        with pytest.raises(LinkConflictError):
            pair_device(
                dev2.device_id,
                asset.asset_id,
                admin_name="viewer",
                actor_role=UserRole.INFRA_VIEWER,
                reassignment=True,
                reason="Attempted reassignment by viewer",
            )


def test_failed_pairing_leaves_database_unchanged(app):
    """An injected failure mid-transaction rolls back all changes completely."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000106", "TAG-106")
        dev = _create_device("VD-DEVICE-0009", DeviceStatus.UNCLAIMED)
        db.session.commit()

        initial_links = AssetDeviceLink.query.count()
        initial_dev_status = dev.status
        initial_asset_status = asset.lifecycle_status

        with pytest.raises(RuntimeError):
            pair_device(
                dev.device_id,
                asset.asset_id,
                admin_name="admin",
                actor_role=UserRole.INFRA_ADMIN,
                _inject_failure=True,
            )

        db.session.expire_all()
        assert AssetDeviceLink.query.count() == initial_links
        d = db.session.get(PhysicalDevice, dev.id)
        a = db.session.get(Asset, asset.id)
        assert d.status == initial_dev_status
        assert a.lifecycle_status == initial_asset_status


def test_token_enrollment_respects_link_rules(app, client):
    """Enrolling with an asset token when the asset already has an active link fails gracefully."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000107", "TAG-107")
        dev1 = _create_device("VD-DEVICE-0010", DeviceStatus.UNCLAIMED)
        db.session.commit()

        pair_device(dev1.device_id, asset.asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)

        # Try enrolling a second device using an enrollment token for asset
        from test_enrollment import create_test_endpoint_payload

        from app.security.tokens import create_token_for_asset

        raw_token, _ = create_token_for_asset(asset.id, created_by="admin")
        payload, _ = create_test_endpoint_payload(token=raw_token, hardware_suffix="second")

        resp = client.post("/api/v1/agents/enroll", json=payload)
        # Should be rejected due to link conflict / invalid enrollment
        assert resp.status_code in (400, 409)

        # Asset still only has 1 active link
        active_links = AssetDeviceLink.query.filter_by(
            asset_id=asset.id,
            relationship_status=RelationshipStatus.ACTIVE,
        ).count()
        assert active_links == 1


def test_db_rejects_duplicate_active_link_even_if_service_bypassed(app):
    """Raw SQL insertion of a second ACTIVE link fails at the DB level via partial unique index."""
    with app.app_context():
        asset = _create_asset("VD-ASSET-000108", "TAG-108")
        dev1 = _create_device("VD-DEVICE-0011", DeviceStatus.UNCLAIMED)
        dev2 = _create_device("VD-DEVICE-0012", DeviceStatus.UNCLAIMED)
        db.session.commit()

        now_str = datetime.now(UTC).isoformat()
        db.session.execute(
            text(
                "INSERT INTO asset_device_links (asset_id, device_id, relationship_status, linked_at, linked_by) "
                "VALUES (:aid, :did, 'ACTIVE', :now, 'test')"
            ),
            {"aid": asset.id, "did": dev1.id, "now": now_str},
        )
        db.session.commit()

        # Second insert directly bypassing Python code must fail at DB level
        with pytest.raises(IntegrityError):
            db.session.execute(
                text(
                    "INSERT INTO asset_device_links (asset_id, device_id, relationship_status, linked_at, linked_by) "
                    "VALUES (:aid, :did, 'ACTIVE', :now, 'test')"
                ),
                {"aid": asset.id, "did": dev2.id, "now": now_str},
            )
            db.session.commit()
        db.session.rollback()


def test_concurrent_pairing_same_asset(tmp_path):
    """Concurrent pairing attempts on the same asset: exactly one succeeds, rest get LinkConflictError."""
    db_file = tmp_path / "concurrent_test.db"
    db_url = f"sqlite:///{db_file}"
    engine_opts = {"connect_args": {"timeout": 30}}

    test_app = create_app("testing", test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts})
    with test_app.app_context():
        with db.engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()
        db.create_all()
        asset = _create_asset("VD-ASSET-000109", "TAG-109")
        devices = [_create_device(f"VD-DEVICE-CONC-{i}", DeviceStatus.UNCLAIMED) for i in range(8)]
        db.session.commit()
        asset_id = asset.asset_id
        device_ids = [d.device_id for d in devices]

    def attempt_pair(dev_id):
        worker_app = create_app("testing", test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts})
        with worker_app.app_context():
            try:
                pair_device(dev_id, asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)
                return "SUCCESS"
            except LinkConflictError:
                return "CONFLICT"
            except Exception as e:  # noqa: BLE001
                return f"ERROR: {type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt_pair, device_ids))

    assert results.count("SUCCESS") == 1
    assert results.count("CONFLICT") == 7

    with test_app.app_context():
        active_links = AssetDeviceLink.query.filter_by(
            relationship_status=RelationshipStatus.ACTIVE,
        ).count()
        assert active_links == 1


def test_concurrent_pairing_same_device_two_assets(tmp_path):
    """Concurrent pairing attempts for the same device to two different assets: exactly one succeeds."""
    db_file = tmp_path / "concurrent_dev_test.db"
    db_url = f"sqlite:///{db_file}"
    engine_opts = {"connect_args": {"timeout": 30}}

    test_app = create_app("testing", test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts})
    with test_app.app_context():
        with db.engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()
        db.create_all()
        asset1 = _create_asset("VD-ASSET-000110", "TAG-110")
        asset2 = _create_asset("VD-ASSET-000111", "TAG-111")
        dev = _create_device("VD-DEVICE-CONC-DEV", DeviceStatus.UNCLAIMED)
        db.session.commit()
        a1_id, a2_id = asset1.asset_id, asset2.asset_id
        d_id = dev.device_id

    def attempt_pair(asset_id):
        worker_app = create_app("testing", test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts})
        with worker_app.app_context():
            try:
                pair_device(d_id, asset_id, admin_name="admin", actor_role=UserRole.INFRA_ADMIN)
                return "SUCCESS"
            except LinkConflictError:
                return "CONFLICT"
            except Exception as e:  # noqa: BLE001
                return f"ERROR: {type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt_pair, [a1_id, a2_id]))

    assert results.count("SUCCESS") == 1
    assert results.count("CONFLICT") == 1

    with test_app.app_context():
        active_links = AssetDeviceLink.query.filter_by(
            relationship_status=RelationshipStatus.ACTIVE,
        ).count()
        assert active_links == 1


def test_no_direct_asset_device_link_instantiation_outside_identity_service():
    """Verify architectural invariant: no code path outside identity_service instantiates AssetDeviceLink."""
    backend_app_dir = os.path.join(os.path.dirname(__file__), "..", "app")
    violations = []
    pattern = re.compile(r"(?<!class\s)AssetDeviceLink\(")

    for root, _, files in os.walk(backend_app_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            rel_path = os.path.relpath(path, backend_app_dir)
            # Allowed only in identity_service.py
            if rel_path in ("services/identity_service.py", "services\\identity_service.py"):
                continue
            with open(path, encoding="utf-8") as fp:
                for line_no, line in enumerate(fp, start=1):
                    if pattern.search(line) and not line.strip().startswith("#"):
                        violations.append(f"{rel_path}:{line_no}: {line.strip()}")

    assert not violations, f"Direct AssetDeviceLink instantiation found outside identity_service: {violations}"

