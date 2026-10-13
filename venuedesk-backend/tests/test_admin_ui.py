"""Integration tests for Phase 10: Admin Web UI, CSRF defense, and pairing token lifecycle."""
from datetime import UTC, datetime

from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    AssetVerificationStatus,
    DeviceInventory,
    DeviceStatus,
    EnrollmentToken,
    EnrollmentTokenStatus,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    Telemetry,
    User,
    UserRole,
    generate_device_id,
    generate_next_asset_id,
)


def create_admin_user(app, username="ui_admin", role=UserRole.INFRA_ADMIN) -> int:
    """Helper creating an administrative user for session authentication."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, role=role)
            user.set_password("adminsecret123")
            db.session.add(user)
            db.session.commit()
        return user.id


def create_demo_asset_and_device(app):
    """Helper setting up an asset, device, link, inventory, and telemetry sample."""
    dev_id = generate_device_id()
    now = datetime.now(UTC)

    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag=f"TAG-{dev_id[-6:]}",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.PENDING_VERIFICATION,
            verification_status=AssetVerificationStatus.UNVERIFIED,
            location_label="Lab 1, Bench 3",
        )
        db.session.add(asset)
        db.session.flush()

        dev = PhysicalDevice(
            device_id=dev_id,
            device_public_key="base64pubkeyplaceholder==",
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

        inv = DeviceInventory(
            device_id=dev.id,
            hostname="lab-desktop-01",
            ip_addresses=["192.168.1.100"],
            cpu_model="AMD Ryzen 7 5700G",
            cpu_cores=8,
            ram_total_mb=16384,
            os_summary="Ubuntu 24.04 LTS",
            agent_version="0.1.0",
        )
        db.session.add(inv)

        telem = Telemetry(
            device_id=dev.id,
            timestamp=now,
            cpu_percent=25.5,
            memory_percent=55.0,
            disk_percent=42.0,
            uptime=7200,
        )
        db.session.add(telem)

        os_inst = OSInstallation(
            device_id=dev.id,
            os_family="LINUX",
            os_name="Ubuntu",
            os_version="24.04",
            architecture="x86_64",
            os_machine_id_hash="mid-sample-hash",
            agent_instance_id="inst-sample-uuid",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)
        db.session.commit()

        return dev.device_id, asset.asset_id


def test_ui_unauthenticated_access_redirects_to_login(client):
    """Test unauthenticated GET access to admin UI redirects to login."""
    resp = client.get("/admin/infrastructure/devices", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_ui_login_and_logout_flow(client, app):
    """Test web administrator session sign in and sign out."""
    create_admin_user(app, username="signin_admin")

    # 1. Sign in with bad password fails
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid_csrf_token"

    bad_resp = client.post(
        "/admin/infrastructure/login",
        data={"username": "signin_admin", "password": "wrongpassword", "csrf_token": "valid_csrf_token"},
    )
    assert bad_resp.status_code == 200
    assert b"Invalid username or password" in bad_resp.data

    # 2. Sign in with correct password succeeds and redirects
    ok_resp = client.post(
        "/admin/infrastructure/login",
        data={"username": "signin_admin", "password": "adminsecret123", "csrf_token": "valid_csrf_token"},
        follow_redirects=True,
    )
    assert ok_resp.status_code == 200
    assert b"Managed Endpoints" in ok_resp.data

    # 3. Sign out clears session
    out_resp = client.get("/admin/infrastructure/logout", follow_redirects=True)
    assert out_resp.status_code == 200
    assert b"Sign In" in out_resp.data


def test_devices_list_page_and_filtering(client, app):
    """Test devices list page renders correctly with status and online indicators."""
    admin_id = create_admin_user(app, username="list_admin")
    dev_id, asset_id = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id

    resp = client.get("/admin/infrastructure/devices")
    assert resp.status_code == 200
    assert dev_id.encode() in resp.data
    assert asset_id.encode() in resp.data
    assert b"lab-desktop-01" not in resp.data  # Hostname is in detail or search
    assert b"Ubuntu 24.04 LTS" in resp.data


def test_device_detail_page_spec_blocks_and_sparkline(client, app):
    """Test device detail page renders Spec §42 blocks, OS installations, and telemetry chart."""
    admin_id = create_admin_user(app, username="detail_admin")
    dev_id, asset_id = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id

    resp = client.get(f"/admin/infrastructure/devices/{dev_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    # Spec §42 sections present
    assert "Institutional Asset Mapping" in html
    assert "Physical Device Identity" in html
    assert "Current Technical State & Telemetry" in html
    assert "Observed Hardware Inventory" in html
    assert "Operating System Installations (Spec §43)" in html
    assert "Asset Link History (Spec §44)" in html
    assert "Remote Maintenance & Diagnostic Jobs" in html
    assert "telemetryChart" in html
    assert asset_id in html


def test_pairing_token_generated_and_shown_once_only(client, app):
    """Test pairing token generation modal: raw token is displayed once only and never stored in plaintext."""
    admin_id = create_admin_user(app, username="token_admin")
    _, asset_id = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "test_csrf"

    # POST to generate pairing token
    post_resp = client.post(
        f"/admin/infrastructure/assets/{asset_id}/pairing-token",
        data={"csrf_token": "test_csrf"},
    )
    assert post_resp.status_code == 200
    html = post_resp.data.decode("utf-8")

    # Must contain single-use token and warning
    assert "Single-Use Pairing Token Generated" in html
    assert "PAIR-" in html
    assert "venuedesk-agent enroll" in html

    # Extract raw token from response
    import re
    token_match = re.search(r"PAIR-[A-Za-z0-9_\-]+", html)
    assert token_match is not None
    raw_token = token_match.group(0)

    # Database verification: raw token MUST NOT be in the DB (only hash is stored)
    with app.app_context():
        token_rows = EnrollmentToken.query.filter_by(status=EnrollmentTokenStatus.ACTIVE).all()
        assert len(token_rows) >= 1
        for row in token_rows:
            assert row.token_hash != raw_token
            assert raw_token not in str(row.__dict__)

    # Subsequent GET on assets page: raw token is NEVER displayed again
    get_resp = client.get("/admin/infrastructure/assets")
    assert get_resp.status_code == 200
    assert raw_token.encode() not in get_resp.data


def test_csrf_protection_rejects_missing_or_tampered_token(client, app):
    """Security check: Mutating POST requests without valid CSRF token are rejected."""
    admin_id = create_admin_user(app, username="csrf_admin")
    _, asset_id = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "secret_session_csrf_42"

    # 1. Missing CSRF token
    resp_missing = client.post(
        f"/admin/infrastructure/assets/{asset_id}/pairing-token",
        data={},
        follow_redirects=True,
    )
    assert b"invalid or expired CSRF token" in resp_missing.data

    # 2. Tampered / wrong CSRF token
    resp_bad = client.post(
        f"/admin/infrastructure/assets/{asset_id}/pairing-token",
        data={"csrf_token": "attacker_forged_token"},
        follow_redirects=True,
    )
    assert b"invalid or expired CSRF token" in resp_bad.data


def test_unclaimed_device_pairing_workflow(client, app):
    """Test unclaimed device discovery and manual pairing to asset."""
    admin_id = create_admin_user(app, username="pair_admin")
    now = datetime.now(UTC)

    with app.app_context():
        # Unclaimed device
        dev = PhysicalDevice(
            device_id=generate_device_id(),
            device_public_key="unclaimed_pubkey==",
            status=DeviceStatus.UNCLAIMED,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(dev)

        # Unlinked asset
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag="UNPAIRED-TAG",
            asset_type=AssetType.DESKTOP,
        )
        db.session.add(asset)
        db.session.commit()
        dev_id = dev.device_id
        asset_id = asset.asset_id

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "pair_csrf"

    # View unclaimed devices list
    list_resp = client.get("/admin/infrastructure/unclaimed")
    assert list_resp.status_code == 200
    assert dev_id.encode() in list_resp.data

    # Submit pairing form
    pair_resp = client.post(
        f"/admin/infrastructure/unclaimed/{dev_id}/pair",
        data={"asset_id": asset_id, "csrf_token": "pair_csrf"},
        follow_redirects=True,
    )
    assert pair_resp.status_code == 200

    # Verify device status is now PENDING_VERIFICATION
    with app.app_context():
        updated_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert updated_dev.status == DeviceStatus.PENDING_VERIFICATION


def test_verify_device_spec_57_form_submission(client, app):
    """Test physical device verification form (Spec §57)."""
    admin_id = create_admin_user(app, username="verify_admin")
    dev_id, _asset_id = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "verify_csrf"

    # GET verification form
    get_resp = client.get(f"/admin/infrastructure/devices/{dev_id}/verify")
    assert get_resp.status_code == 200
    assert b"Physical Verification Form (Spec \xc2\xa757)" in get_resp.data or b"Physical Verification Form" in get_resp.data

    # POST verification form
    post_resp = client.post(
        f"/admin/infrastructure/devices/{dev_id}/verify",
        data={
            "csrf_token": "verify_csrf",
            "verification_method": "ADMIN_CONFIRMATION",
            "observed_asset_tag": "TAG-CONFIRMED",
            "observed_serial": "SN-CONFIRMED",
            "observed_location": "Building B, Room 101",
            "notes": "Audited in person.",
        },
        follow_redirects=True,
    )
    assert post_resp.status_code == 200
    assert b"Physical verification confirmed" in post_resp.data

    # Confirm device is ACTIVE and asset is VERIFIED / IN_SERVICE
    with app.app_context():
        verified_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert verified_dev.status == DeviceStatus.ACTIVE
        assert verified_dev.last_verified_at is not None
        active_link = next(l for l in verified_dev.links if l.relationship_status == RelationshipStatus.ACTIVE)
        assert active_link.asset.verification_status == AssetVerificationStatus.VERIFIED
        assert active_link.asset.lifecycle_status == AssetLifecycleStatus.IN_SERVICE


def test_suspend_and_unsuspend_device_ui_workflow(client, app):
    """Test suspending and unsuspending an endpoint via admin UI creates audit rows."""
    admin_id = create_admin_user(app, username="suspend_admin")
    dev_id, _ = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "action_csrf"

    # 1. Suspend device
    resp = client.post(
        f"/admin/infrastructure/devices/{dev_id}/suspend",
        data={"csrf_token": "action_csrf", "reason": "Security investigation"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"has been suspended" in resp.data

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.SUSPENDED

        # Verify audit log created
        from app.models import AuditAction, AuditLog
        log = (
            AuditLog.query.filter_by(entity_id=dev_id, action=AuditAction.DEVICE_SUSPENDED)
            .first()
        )
        assert log is not None
        assert log.actor_id == "suspend_admin"

    # 2. Unsuspend device
    resp_un = client.post(
        f"/admin/infrastructure/devices/{dev_id}/unsuspend",
        data={"csrf_token": "action_csrf", "reason": "Investigation cleared"},
        follow_redirects=True,
    )
    assert resp_un.status_code == 200
    assert b"restored to ACTIVE status" in resp_un.data

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.ACTIVE


def test_reassign_device_ui_workflow(client, app):
    """Test reassigning endpoint to another institutional asset via admin UI."""
    admin_id = create_admin_user(app, username="reassign_admin")
    dev_id, _old_asset_id = create_demo_asset_and_device(app)

    with app.app_context():
        old_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        old_link = next(l for l in old_dev.links if l.relationship_status == RelationshipStatus.ACTIVE)
        old_asset_tag = old_link.asset.asset_tag

        # Create new target asset
        target_asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag=f"TARGET-TAG-{dev_id[-4:]}",
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.PENDING_AGENT,
        )
        db.session.add(target_asset)
        db.session.commit()
        target_asset_id = target_asset.asset_id

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "reassign_csrf"

    # 1. Wrong confirmation tag rejected
    bad_resp = client.post(
        f"/admin/infrastructure/devices/{dev_id}/reassign",
        data={
            "csrf_token": "reassign_csrf",
            "target_asset_id": target_asset_id,
            "confirm_asset_tag": "WRONG-TAG",
            "reason": "Relocation",
        },
        follow_redirects=True,
    )
    assert b"Confirmation tag mismatch" in bad_resp.data

    # 2. Correct confirmation succeeds
    ok_resp = client.post(
        f"/admin/infrastructure/devices/{dev_id}/reassign",
        data={
            "csrf_token": "reassign_csrf",
            "target_asset_id": target_asset_id,
            "confirm_asset_tag": old_asset_tag,
            "reason": "Relocated to Lab 2",
        },
        follow_redirects=True,
    )
    assert ok_resp.status_code == 200
    assert b"successfully reassigned" in ok_resp.data

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        active_link = next(l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE)
        assert active_link.asset.asset_id == target_asset_id


def test_retire_and_revoke_device_ui_workflow(client, app):
    """Test retiring and revoking device with typed confirmation."""
    admin_id = create_admin_user(app, username="retire_admin")
    dev_id, _ = create_demo_asset_and_device(app)

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        active_link = next(l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE)
        tag = active_link.asset.asset_tag

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id
        sess["_csrf_token"] = "retire_csrf"

    # Retire
    resp_retire = client.post(
        f"/admin/infrastructure/devices/{dev_id}/retire",
        data={
            "csrf_token": "retire_csrf",
            "confirm_asset_tag": tag,
            "reason": "Equipment decommissioned",
        },
        follow_redirects=True,
    )
    assert resp_retire.status_code == 200
    assert b"has been retired" in resp_retire.data

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev.status == DeviceStatus.RETIRED
        # No active links
        assert not any(l.relationship_status == RelationshipStatus.ACTIVE for l in dev.links)


def test_viewer_role_read_only_access(client, app):
    """Test that infra_viewer role can view pages but mutations fail with 403 or redirect."""
    viewer_id = create_admin_user(app, username="viewer_user", role=UserRole.INFRA_VIEWER)
    dev_id, _ = create_demo_asset_and_device(app)

    with client.session_transaction() as sess:
        sess["user_id"] = viewer_id
        sess["_csrf_token"] = "viewer_csrf"

    # Viewer can view device list and detail
    resp_list = client.get("/admin/infrastructure/devices")
    assert resp_list.status_code == 200

    resp_detail = client.get(f"/admin/infrastructure/devices/{dev_id}")
    assert resp_detail.status_code == 200

    # Viewer cannot perform mutating action
    resp_suspend = client.post(
        f"/admin/infrastructure/devices/{dev_id}/suspend",
        data={"csrf_token": "viewer_csrf", "reason": "Unauthorized"},
        follow_redirects=True,
    )
    assert b"Access denied" in resp_suspend.data

    # Viewer cannot access API mutation
    api_suspend = client.post(
        f"/api/v1/admin/devices/{dev_id}/suspend",
        headers={"Authorization": "Basic " + "dmlld2VyX3VzZXI6YWRtaW5zZWNyZXQxMjM="},
        json={"reason": "Unauthorized API"},
    )
    assert api_suspend.status_code == 403


def test_devices_list_query_count_budget_no_n_plus_one(client, app):
    """Test that listing 50 devices stays within a strict query budget (assert <= 10 queries, no N+1)."""
    admin_id = create_admin_user(app, username="query_admin")
    now = datetime.now(UTC)

    with app.app_context():
        for i in range(50):
            d_id = f"VD-BULK-{i:04d}"
            dev = PhysicalDevice(
                device_id=d_id,
                device_public_key="bulkpubkey==",
                status=DeviceStatus.ACTIVE,
                first_seen=now,
                last_seen=now,
            )
            db.session.add(dev)
            db.session.flush()

            asset = Asset(
                asset_id=f"VD-ASSET-B{i:04d}",
                asset_tag=f"TAG-B{i:04d}",
                asset_type=AssetType.DESKTOP,
            )
            db.session.add(asset)
            db.session.flush()

            link = AssetDeviceLink(
                asset_id=asset.id,
                device_id=dev.id,
                relationship_status=RelationshipStatus.ACTIVE,
                linked_at=now,
            )
            db.session.add(link)

            inv = DeviceInventory(
                device_id=dev.id,
                hostname=f"bulk-host-{i}",
                os_summary="Linux",
                agent_version="1.0.0",
            )
            db.session.add(inv)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = admin_id

    from sqlalchemy import event

    query_count = 0

    def query_listener(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        query_count += 1

    with app.app_context():
        event.listen(db.engine, "before_cursor_execute", query_listener)
        try:
            resp = client.get("/admin/infrastructure/devices")
            assert resp.status_code == 200
            # Listing 50 items must not do 50+ queries (no N+1). With joinedload/subqueryload it stays under 10.
            assert query_count <= 10, f"Query count was {query_count}, expected <= 10 (N+1 query problem detected)"
        finally:
            event.remove(db.engine, "before_cursor_execute", query_listener)
