"""Telemetry service for high-frequency metrics recording, querying, and retention pruning."""
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.extensions import db
from app.models import PhysicalDevice, Telemetry

logger = logging.getLogger(__name__)


def _parse_timestamp(ts_val: Any) -> datetime:
    """Parse timestamp from ISO string, unix epoch number, or fallback to current UTC."""
    if isinstance(ts_val, (int, float)):
        return datetime.fromtimestamp(ts_val, tz=UTC)
    if isinstance(ts_val, str) and ts_val.strip():
        try:
            # Handle trailing Z
            clean_str = ts_val.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except (ValueError, TypeError):
            pass
    return datetime.now(UTC)


def record_telemetry(device_id: int, samples: list[dict[str, Any]]) -> int:
    """Batch insert telemetry samples for a given physical device."""
    if not samples:
        return 0

    records: list[Telemetry] = []
    for s in samples:
        ts = _parse_timestamp(s.get("timestamp"))
        rec = Telemetry(
            device_id=device_id,
            timestamp=ts,
            cpu_percent=float(s.get("cpu_percent", 0.0)),
            memory_percent=float(s.get("memory_percent", 0.0)),
            disk_percent=float(s.get("disk_percent", 0.0)),
            network_rx=int(s.get("network_rx", 0)),
            network_tx=int(s.get("network_tx", 0)),
            uptime=float(s.get("uptime", 0.0)),
            load_average=float(s["load_average"]) if s.get("load_average") is not None else None,
            gpu_percent=float(s["gpu_percent"]) if s.get("gpu_percent") is not None else None,
            gpu_mem_percent=float(s["gpu_mem_percent"]) if s.get("gpu_mem_percent") is not None else None,
            temperature_c=float(s["temperature_c"]) if s.get("temperature_c") is not None else None,
        )
        records.append(rec)

    db.session.bulk_save_objects(records)
    db.session.commit()
    logger.debug("Recorded %d telemetry samples for device ID %d", len(records), device_id)
    return len(records)


def purge_telemetry(older_than_days: int = 30) -> int:
    """Purge telemetry records older than the specified retention threshold."""
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    deleted = db.session.query(Telemetry).filter(Telemetry.timestamp < cutoff).delete(synchronize_session=False)
    db.session.commit()
    logger.info("Purged %d telemetry records older than %d days", deleted, older_than_days)
    return deleted


def get_device_telemetry(
    device_identifier: str | int,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Retrieve telemetry time series for a physical device."""
    # Resolve device if passed string device_id (VD-DEVICE-...)
    dev_pk = None
    if isinstance(device_identifier, int):
        dev_pk = device_identifier
    else:
        dev = PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if dev:
            dev_pk = dev.id
        else:
            try:
                dev_pk = int(device_identifier)
            except ValueError:
                return []

    query = Telemetry.query.filter_by(device_id=dev_pk)
    if from_time:
        query = query.filter(Telemetry.timestamp >= from_time)
    if to_time:
        query = query.filter(Telemetry.timestamp <= to_time)

    records = query.order_by(Telemetry.timestamp.desc()).limit(min(limit, 1000)).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "cpu_percent": r.cpu_percent,
            "memory_percent": r.memory_percent,
            "disk_percent": r.disk_percent,
            "network_rx": r.network_rx,
            "network_tx": r.network_tx,
            "uptime": r.uptime,
            "load_average": r.load_average,
            "gpu_percent": r.gpu_percent,
            "gpu_mem_percent": r.gpu_mem_percent,
            "temperature_c": r.temperature_c,
        }
        for r in records
    ]
