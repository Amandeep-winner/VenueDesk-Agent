"""Device lifecycle and offline marking service."""

import logging
from datetime import UTC, datetime, timedelta

from app.extensions import db
from app.models import (
    DeviceEvent,
    DeviceEventType,
    DeviceStatus,
    EventSeverity,
    PhysicalDevice,
)

logger = logging.getLogger(__name__)


def mark_offline_devices(heartbeat_interval_seconds: int = 60) -> list[str]:
    """Mark active devices as OFFLINE if their last heartbeat exceeds 3x heartbeat interval."""
    skew_window = heartbeat_interval_seconds * 3
    cutoff = datetime.now(UTC) - timedelta(seconds=skew_window)

    stale_devices = PhysicalDevice.query.filter(
        PhysicalDevice.status == DeviceStatus.ACTIVE,
        PhysicalDevice.last_seen < cutoff,
    ).all()

    marked_ids: list[str] = []
    now = datetime.now(UTC)

    for device in stale_devices:
        device.status = DeviceStatus.OFFLINE
        marked_ids.append(device.device_id)

        event = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.HEARTBEAT_MISSED,
            severity=EventSeverity.MEDIUM,
            payload={
                "message": f"Missed heartbeats for over {skew_window} seconds",
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            },
            occurred_at=now,
            created_at=now,
        )
        db.session.add(event)
        logger.info(
            "Marked device %s as OFFLINE (last_seen=%s)", device.device_id, device.last_seen
        )

    if marked_ids:
        db.session.commit()

    return marked_ids


def revoke_device_credential(
    device_identifier: int | str,
    credential_version: int | None = None,
    reason: str = "Administrative revocation",
    actor: str = "system",
) -> bool:
    """Revoke credentials for a device, update status, and write an immutable audit log."""
    from app.models.audit import ActorType, AuditAction, AuditLog
    from app.models.device import DeviceCredential

    device = None
    if isinstance(device_identifier, int):
        device = db.session.get(PhysicalDevice, device_identifier)
    else:
        device = PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()

    if not device:
        return False

    now = datetime.now(UTC)
    query = DeviceCredential.query.filter_by(device_id=device.id, status="ACTIVE")
    if credential_version is not None:
        query = query.filter_by(credential_version=credential_version)

    creds = query.all()
    for cred in creds:
        cred.status = "REVOKED"
        cred.revoked_at = now

    db.session.add(
        AuditLog(
            actor_id=actor,
            actor_type=ActorType.USER if actor != "system" else ActorType.SYSTEM,
            action=AuditAction.CREDENTIAL_ROTATED,
            entity_type="device",
            entity_id=device.device_id,
            new_value={
                "status": "REVOKED",
                "credential_version": credential_version,
                "reason": reason,
            },
        )
    )
    db.session.commit()
    logger.info(
        "Revoked credential(s) for device %s (version=%s)", device.device_id, credential_version
    )
    return True
