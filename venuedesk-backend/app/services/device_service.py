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
        logger.info("Marked device %s as OFFLINE (last_seen=%s)", device.device_id, device.last_seen)

    if marked_ids:
        db.session.commit()

    return marked_ids
