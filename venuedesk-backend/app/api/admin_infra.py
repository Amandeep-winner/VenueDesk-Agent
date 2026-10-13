import base64
import io
import json
import logging
from datetime import UTC, datetime, timedelta

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.orm import selectinload

from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AssetDeviceLink,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceIdentityEvidence,
    DeviceJob,
    DeviceRecoveryRequest,
    DeviceStatus,
    OSInstallation,
    PhysicalDevice,
    RelationshipStatus,
    Telemetry,
    User,
    UserRole,
)
from app.security.csrf import require_csrf
from app.security.rbac import require_ui_role
from app.security.tokens import create_token_for_asset
from app.services.identity_service import (
    LinkConflictError,
    approve_device_recovery,
    approve_hardware_change,
    pair_device,
    pair_unclaimed_device,
    verify_device_physical,
)
from app.services.job_service import create_job

admin_infra_bp = Blueprint("admin_infra", __name__, url_prefix="/admin/infrastructure")


def _is_device_online(device: PhysicalDevice) -> bool:
    """Device is considered online if last_seen was within 3x heartbeat interval (default 3 mins)."""
    if not device.last_seen:
        return False
    threshold = datetime.now(UTC) - timedelta(seconds=180)
    dev_last = device.last_seen if device.last_seen.tzinfo else device.last_seen.replace(tzinfo=UTC)
    return dev_last >= threshold


@admin_infra_bp.route("/login", methods=["GET", "POST"])
@require_csrf
def login():
    """Authentication view for web administrator session."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            flash(f"Welcome back, {user.username}!", "success")
            next_url = request.form.get("next") or url_for("admin_infra.devices_list")
            return redirect(next_url)

        flash("Invalid username or password.", "danger")

    return render_template("infrastructure/login.html", next_url=request.args.get("next", ""))


@admin_infra_bp.route("/logout", methods=["GET"])
def logout():
    """Sign out of administrator session."""
    session.pop("user_id", None)
    flash("You have been signed out.", "info")
    return redirect(url_for("admin_infra.login"))


@admin_infra_bp.route("/", methods=["GET"])
@admin_infra_bp.route("/devices", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def devices_list():
    """List managed endpoints with filtering by status, online state, OS, and query."""
    status_filter = request.args.get("status", "").strip()
    online_filter = request.args.get("online", "").strip()
    q_filter = request.args.get("q", "").strip()
    os_filter = request.args.get("os", "").strip()

    query = (
        PhysicalDevice.query.filter(PhysicalDevice.status != DeviceStatus.UNCLAIMED)
        .options(
            selectinload(PhysicalDevice.inventory),
            selectinload(PhysicalDevice.links).selectinload(AssetDeviceLink.asset),
        )
    )

    if status_filter:
        try:
            status_enum = DeviceStatus(status_filter)
            query = query.filter_by(status=status_enum)
        except ValueError:
            pass

    devices_all = query.order_by(PhysicalDevice.last_seen.desc().nullslast()).all()
    results = []
    unclaimed_count = PhysicalDevice.query.filter_by(status=DeviceStatus.UNCLAIMED).count()

    for dev in devices_all:
        is_online = _is_device_online(dev)
        if online_filter == "online" and not is_online:
            continue
        if online_filter == "offline" and is_online:
            continue

        inv = dev.inventory
        if os_filter and inv:
            os_summary = (inv.os_summary or "").upper()
            if os_filter not in os_summary:
                continue

        active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
        asset = active_link.asset if active_link else None

        if q_filter:
            q_lower = q_filter.lower()
            match = (
                q_lower in dev.device_id.lower()
                or (inv and inv.hostname and q_lower in inv.hostname.lower())
                or (inv and inv.ip_addresses and any(q_lower in ip.lower() for ip in inv.ip_addresses))
                or (asset and asset.asset_tag and q_lower in asset.asset_tag.lower())
                or (asset and q_lower in asset.asset_id.lower())
            )
            if not match:
                continue

        results.append({
            "device": dev,
            "asset": asset,
            "inventory": inv,
            "is_online": is_online,
        })

    all_statuses = [s.value for s in DeviceStatus if s != DeviceStatus.UNCLAIMED]
    return render_template(
        "infrastructure/devices.html",
        devices=results,
        all_statuses=all_statuses,
        filter_status=status_filter,
        filter_online=online_filter,
        filter_q=q_filter,
        filter_os=os_filter,
        unclaimed_count=unclaimed_count,
        active_page="devices",
    )


@admin_infra_bp.route("/devices/<device_id>", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def device_detail(device_id: str):
    """Device detail view matching specification sections 42, 43, and 44."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)

    # Telemetry sparkline data (latest 20 samples)
    telemetry_samples = (
        Telemetry.query.filter_by(device_id=dev.id)
        .order_by(Telemetry.timestamp.desc())
        .limit(20)
        .all()
    )
    telemetry_samples.reverse()

    chart_timestamps = [t.timestamp.strftime("%H:%M:%S") for t in telemetry_samples]
    chart_cpu = [round(t.cpu_percent, 1) for t in telemetry_samples]
    chart_mem = [round(t.memory_percent, 1) for t in telemetry_samples]
    latest_telemetry = telemetry_samples[-1] if telemetry_samples else None

    # OS Installations (§43)
    os_installs = (
        OSInstallation.query.filter_by(device_id=dev.id)
        .order_by(OSInstallation.last_seen.desc())
        .all()
    )

    # Asset Link History (§44)
    asset_links = (
        AssetDeviceLink.query.filter_by(device_id=dev.id)
        .order_by(AssetDeviceLink.linked_at.desc())
        .all()
    )

    # Remote jobs history
    jobs = (
        DeviceJob.query.filter_by(device_id=dev.id)
        .order_by(DeviceJob.created_at.desc())
        .limit(25)
        .all()
    )

    # Events history
    events = (
        DeviceEvent.query.filter_by(device_id=dev.id)
        .order_by(DeviceEvent.occurred_at.desc())
        .limit(20)
        .all()
    )

    # Recent audit slice for this device
    audit_slice = (
        AuditLog.query.filter(
            (AuditLog.entity_id == dev.device_id) | (AuditLog.entity_id.like(f"%{dev.device_id}%"))
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(15)
        .all()
    )

    # Available assets for reassignment
    active_asset_subquery = db.select(AssetDeviceLink.asset_id).filter_by(relationship_status=RelationshipStatus.ACTIVE)
    available_assets = Asset.query.filter(~Asset.id.in_(active_asset_subquery)).all()

    return render_template(
        "infrastructure/device_detail.html",
        device=dev,
        active_link=active_link,
        inventory=dev.inventory,
        latest_telemetry=latest_telemetry,
        telemetry_samples=telemetry_samples,
        telemetry_timestamps=chart_timestamps,
        telemetry_cpu=chart_cpu,
        telemetry_mem=chart_mem,
        os_installations=os_installs,
        asset_links=asset_links,
        jobs=jobs,
        events=events,
        audit_slice=audit_slice,
        available_assets=available_assets,
        active_page="devices",
    )


@admin_infra_bp.route("/devices/<device_id>/jobs/dispatch", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def dispatch_device_job(device_id: str):
    """Dispatch an allowlisted remote maintenance or diagnostic job."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    job_type = request.form.get("job_type")
    param_text = request.form.get("payload_param", "").strip()

    payload: dict = {}
    if param_text:
        try:
            payload = json.loads(param_text)
        except json.JSONDecodeError:
            # Handle plain string input as service_name or target
            if job_type == "RESTART_APPROVED_SERVICE":
                payload = {"service_name": param_text}
            elif job_type == "RUN_NETWORK_DIAGNOSTIC":
                payload = {"target": param_text}
            else:
                payload = {"target": param_text}

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"

    try:
        job = create_job(
            device_identifier=dev.id,
            job_type=job_type,
            payload=payload,
            created_by=admin_username,
            expires_in_seconds=3600,
        )
        flash(f"Remote job #{job.id} ({job.job_type.value}) dispatched to endpoint.", "success")
    except (ValueError, TypeError) as exc:
        flash(f"Failed to dispatch job: {exc}", "danger")

    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/unclaimed", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def unclaimed_devices():
    """Unclaimed endpoints discovery page."""
    unclaimed = (
        PhysicalDevice.query.filter_by(status=DeviceStatus.UNCLAIMED)
        .order_by(PhysicalDevice.first_seen.desc())
        .all()
    )

    # Find institutional assets without active link
    active_asset_ids = db.select(AssetDeviceLink.asset_id).filter_by(relationship_status=RelationshipStatus.ACTIVE)
    available_assets = Asset.query.filter(~Asset.id.in_(active_asset_ids)).all()

    return render_template(
        "infrastructure/unclaimed.html",
        unclaimed_devices=unclaimed,
        available_assets=available_assets,
        active_page="unclaimed",
    )


@admin_infra_bp.route("/unclaimed/<device_id>/pair", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def pair_unclaimed_view(device_id: str):
    """Pair an unclaimed device to an institutional asset."""
    asset_id = request.form.get("asset_id")
    if not asset_id:
        flash("Please select an institutional asset to pair.", "warning")
        return redirect(url_for("admin_infra.unclaimed_devices"))

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    try:
        dev, asset = pair_unclaimed_device(device_id, asset_id, admin_name=admin_username)
        flash(f"Successfully paired device {dev.device_id} to asset {asset.asset_id}.", "success")
        return redirect(url_for("admin_infra.device_detail", device_id=dev.device_id))
    except ValueError as exc:
        flash(f"Pairing error: {exc}", "danger")
        return redirect(url_for("admin_infra.unclaimed_devices"))


@admin_infra_bp.route("/assets", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def assets_list():
    """List institutional assets with generate token action."""
    all_assets = Asset.query.order_by(Asset.asset_id.asc()).all()
    for a in all_assets:
        active_link = next((l for l in a.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
        a.active_device = active_link.device if active_link else None

    return render_template(
        "infrastructure/assets.html",
        assets=all_assets,
        generated_token_data=None,
        active_page="assets",
    )


@admin_infra_bp.route("/assets/<asset_id>/pairing-token", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def generate_asset_token_view(asset_id: str):
    """Generate single-use pairing token for an asset, shown once only (spec §4.2)."""
    asset = Asset.query.filter_by(asset_id=asset_id).first_or_404()
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"

    raw_token, tok_obj = create_token_for_asset(asset.id, created_by=admin_username)

    # Generate QR Code vector image (SVG - zero Pillow dependency)
    qr_b64 = None
    try:
        import qrcode
        import qrcode.image.svg
        qr = qrcode.QRCode(box_size=6, border=2, image_factory=qrcode.image.svg.SvgImage)
        qr.add_data(raw_token)
        qr.make(fit=True)
        img = qr.make_image()
        buf = io.BytesIO()
        img.save(buf)
        qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    except (ImportError, OSError, ValueError) as exc:
        logging.getLogger(__name__).debug("QR code generation omitted: %s", exc)

    server_url = request.host_url.rstrip("/")
    cli_command = f"venuedesk-agent enroll --server {server_url} --token {raw_token}"

    token_data = {
        "asset_id": asset.asset_id,
        "raw_token": raw_token,
        "expires_at": tok_obj.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "cli_command": cli_command,
        "qr_base64": qr_b64,
    }

    all_assets = Asset.query.order_by(Asset.asset_id.asc()).all()
    for a in all_assets:
        active_link = next((l for l in a.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
        a.active_device = active_link.device if active_link else None

    flash(f"Single-use pairing token generated for asset {asset.asset_id}.", "warning")
    return render_template(
        "infrastructure/assets.html",
        assets=all_assets,
        generated_token_data=token_data,
        active_page="assets",
    )


@admin_infra_bp.route("/identity-queue", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def identity_queue():
    """Identity changes and recovery requests approval queue."""
    pending_devices = PhysicalDevice.query.filter_by(status=DeviceStatus.PENDING_REVERIFICATION).all()
    for dev in pending_devices:
        dev.latest_snapshot = (
            DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .first()
        )

    recovery_requests = (
        DeviceRecoveryRequest.query.filter_by(status="PENDING")
        .order_by(DeviceRecoveryRequest.created_at.desc())
        .all()
    )

    return render_template(
        "infrastructure/identity_queue.html",
        pending_hardware_changes=pending_devices,
        recovery_requests=recovery_requests,
        active_page="queue",
    )


@admin_infra_bp.route("/identity-queue/<device_id>/approve-hardware-change", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def approve_hardware_change_view(device_id: str):
    """Approve observed hardware changes, restoring device to ACTIVE."""
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    try:
        approve_hardware_change(device_id, admin_name=admin_username)
        flash(f"Hardware change approved for device {device_id}. Status restored to ACTIVE.", "success")
    except ValueError as exc:
        flash(f"Approval error: {exc}", "danger")

    return redirect(url_for("admin_infra.identity_queue"))


@admin_infra_bp.route("/identity-queue/<device_id>/approve-recovery", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def approve_recovery_view(device_id: str):
    """Approve OS reinstall recovery request."""
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    try:
        approve_device_recovery(device_id, admin_name=admin_username)
        flash(f"OS reinstall recovery approved for device {device_id}.", "success")
    except ValueError as exc:
        flash(f"Recovery approval error: {exc}", "danger")

    return redirect(url_for("admin_infra.identity_queue"))


@admin_infra_bp.route("/devices/<device_id>/verify", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN)
def verify_device_view(device_id: str):
    """Render physical verification form matching spec §57."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
    asset = active_link.asset if active_link else None

    return render_template(
        "infrastructure/verify.html",
        device=dev,
        asset=asset,
        active_page="devices",
    )


@admin_infra_bp.route("/devices/<device_id>/verify", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def verify_device_submit(device_id: str):
    """Submit physical verification record (spec §57)."""
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    method = request.form.get("verification_method", "ADMIN_CONFIRMATION")
    observed_tag = request.form.get("observed_asset_tag")
    observed_serial = request.form.get("observed_serial")
    observed_loc = request.form.get("observed_location")
    notes = request.form.get("notes")

    try:
        verify_device_physical(
            device_identifier=device_id,
            admin_name=admin_username,
            verification_method=method,
            observed_asset_tag=observed_tag,
            observed_serial=observed_serial,
            observed_location=observed_loc,
            notes=notes,
        )
        flash(f"Physical verification confirmed for device {device_id}.", "success")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))
    except ValueError as exc:
        flash(f"Verification failed: {exc}", "danger")
        return redirect(url_for("admin_infra.verify_device_view", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/suspend", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def suspend_device_view(device_id: str):
    """Suspend device action with confirmation."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    reason = request.form.get("reason", "").strip()
    if not reason:
        flash("Reason text is required to suspend an endpoint.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    old_status = dev.status.value
    dev.status = DeviceStatus.SUSPENDED

    db.session.add(
        AuditLog(
            actor_id=admin_username,
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_SUSPENDED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": old_status},
            new_value={"status": DeviceStatus.SUSPENDED.value, "reason": reason},
        )
    )
    db.session.commit()
    flash(f"Device {dev.device_id} has been suspended.", "warning")
    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/unsuspend", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def unsuspend_device_view(device_id: str):
    """Restore suspended device to ACTIVE."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    reason = request.form.get("reason", "Administrative restoration").strip()
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"

    old_status = dev.status.value
    dev.status = DeviceStatus.ACTIVE

    db.session.add(
        AuditLog(
            actor_id=admin_username,
            actor_type=ActorType.USER,
            action=AuditAction.IDENTITY_OVERRIDE,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": old_status},
            new_value={"status": DeviceStatus.ACTIVE.value, "reason": reason},
        )
    )
    db.session.commit()
    flash(f"Device {dev.device_id} restored to ACTIVE status.", "success")
    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/retire", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def retire_device_view(device_id: str):
    """Retire device permanently with typed confirmation."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    confirm_tag = request.form.get("confirm_asset_tag", "").strip()
    reason = request.form.get("reason", "").strip()

    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
    expected_tag = active_link.asset.asset_tag if (active_link and active_link.asset) else dev.device_id

    if confirm_tag != expected_tag:
        flash(f"Confirmation tag mismatch. Expected '{expected_tag}'.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    if not reason:
        flash("Reason is required to retire an endpoint.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    now = datetime.now(UTC)
    old_status = dev.status.value
    dev.status = DeviceStatus.RETIRED

    if active_link:
        active_link.relationship_status = RelationshipStatus.CLOSED
        active_link.unlinked_at = now
        active_link.reason = f"Device retired: {reason}"
        db.session.add(
            AuditLog(
                actor_id=admin_username,
                actor_type=ActorType.USER,
                action=AuditAction.DEVICE_UNLINKED,
                entity_type="link",
                entity_id=f"{active_link.asset.asset_id}:{dev.device_id}",
                new_value={"relationship_status": "CLOSED", "reason": reason},
            )
        )

    db.session.add(
        AuditLog(
            actor_id=admin_username,
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_RETIRED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": old_status},
            new_value={"status": DeviceStatus.RETIRED.value, "reason": reason},
        )
    )
    db.session.commit()
    flash(f"Device {dev.device_id} has been retired.", "secondary")
    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/rotate-credential", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def rotate_credential_view(device_id: str):
    """Rotate credentials for endpoint and present one-time re-enrollment token."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    reason = request.form.get("reason", "Administrative rotation").strip()

    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
    asset_id = active_link.asset_id if active_link else None

    from app.security.tokens import create_token_for_device
    raw_token, token_obj = create_token_for_device(
        device_id=dev.id,
        created_by=admin_username,
        ttl_hours=24,
        asset_id=asset_id,
    )

    db.session.add(
        AuditLog(
            actor_id=admin_username,
            actor_type=ActorType.USER,
            action=AuditAction.CREDENTIAL_ROTATED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"credential_version": dev.credential_version},
            new_value={"token_id": token_obj.id, "reason": reason},
        )
    )
    db.session.commit()
    flash(f"New enrollment token generated for credential rotation: {raw_token}", "warning")
    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/revoke", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def revoke_device_view(device_id: str):
    """Revoke endpoint credentials with confirmation."""
    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    confirm_tag = request.form.get("confirm_asset_tag", "").strip()
    reason = request.form.get("reason", "").strip()

    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
    expected_tag = active_link.asset.asset_tag if (active_link and active_link.asset) else dev.device_id

    if confirm_tag != expected_tag:
        flash(f"Confirmation tag mismatch. Expected '{expected_tag}'.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    if not reason:
        flash("Reason is required to revoke an endpoint.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"
    now = datetime.now(UTC)
    old_status = dev.status.value
    dev.status = DeviceStatus.REVOKED

    for cred in dev.credentials:
        cred.status = "REVOKED"
        cred.revoked_at = now

    if active_link:
        active_link.relationship_status = RelationshipStatus.CLOSED
        active_link.unlinked_at = now
        active_link.reason = f"Device revoked: {reason}"
        db.session.add(
            AuditLog(
                actor_id=admin_username,
                actor_type=ActorType.USER,
                action=AuditAction.DEVICE_UNLINKED,
                entity_type="link",
                entity_id=f"{active_link.asset.asset_id}:{dev.device_id}",
                new_value={"relationship_status": "CLOSED", "reason": reason},
            )
        )

    db.session.add(
        AuditLog(
            actor_id=admin_username,
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_REVOKED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": old_status},
            new_value={"status": DeviceStatus.REVOKED.value, "reason": reason},
        )
    )
    db.session.commit()
    flash(f"Device {dev.device_id} has been revoked.", "danger")
    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/devices/<device_id>/reassign", methods=["POST"])
@require_ui_role(UserRole.INFRA_ADMIN)
@require_csrf
def reassign_device_view(device_id: str):
    """Reassign device to a different institutional asset with confirmation."""
    target_asset_id = request.form.get("target_asset_id", "").strip()
    reason = request.form.get("reason", "").strip()
    confirm_tag = request.form.get("confirm_asset_tag", "").strip()

    if not target_asset_id:
        flash("Target asset ID is required.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    if not reason:
        flash("Reason is required for reassignment.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    dev = PhysicalDevice.query.filter_by(device_id=device_id).first_or_404()
    active_link = next((l for l in dev.links if l.relationship_status == RelationshipStatus.ACTIVE), None)
    expected_tag = active_link.asset.asset_tag if (active_link and active_link.asset) else dev.device_id

    if confirm_tag != expected_tag:
        flash(f"Confirmation tag mismatch. Expected current asset tag '{expected_tag}'.", "danger")
        return redirect(url_for("admin_infra.device_detail", device_id=device_id))

    admin_username = g.current_user.username if hasattr(g, "current_user") and g.current_user else "admin"

    try:
        pair_device(
            device_identifier=device_id,
            asset_identifier=target_asset_id,
            admin_name=admin_username,
            actor_role=UserRole.INFRA_ADMIN,
            reassignment=True,
            reason=reason,
        )
        flash(f"Device {device_id} successfully reassigned to asset {target_asset_id}.", "success")
    except (ValueError, LinkConflictError) as exc:
        flash(f"Reassignment failed: {exc}", "danger")

    return redirect(url_for("admin_infra.device_detail", device_id=device_id))


@admin_infra_bp.route("/audit", methods=["GET"])
@require_ui_role(UserRole.INFRA_ADMIN, UserRole.INFRA_VIEWER)
def audit_logs_view():
    """Audit log viewer with filter support."""
    action_filter = request.args.get("action", "").strip()
    q_filter = request.args.get("q", "").strip()

    query = AuditLog.query

    if action_filter:
        try:
            action_enum = AuditAction(action_filter)
            query = query.filter_by(action=action_enum)
        except ValueError:
            pass

    if q_filter:
        query = query.filter(
            (AuditLog.actor_id.ilike(f"%{q_filter}%"))
            | (AuditLog.entity_id.ilike(f"%{q_filter}%"))
            | (AuditLog.entity_type.ilike(f"%{q_filter}%"))
        )

    logs = query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    all_actions = [a.value for a in AuditAction]

    return render_template(
        "infrastructure/audit.html",
        logs=logs,
        all_actions=all_actions,
        filter_action=action_filter,
        filter_q=q_filter,
        active_page="audit",
    )
