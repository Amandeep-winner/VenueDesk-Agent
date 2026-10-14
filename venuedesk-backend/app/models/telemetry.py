"""Telemetry and device event models."""

from datetime import UTC, datetime

from sqlalchemy import JSON, BigInteger, Column, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import DeviceEventType, EventSeverity


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class Telemetry(db.Model):
    """High-frequency device metrics time series."""

    __tablename__ = "telemetry"
    __table_args__ = (Index("idx_telemetry_device_timestamp", "device_id", "timestamp"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(
        Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    cpu_percent = Column(Float, nullable=False)
    memory_percent = Column(Float, nullable=False)
    disk_percent = Column(Float, nullable=False)
    network_rx = Column(BigInteger, nullable=False, default=0)
    network_tx = Column(BigInteger, nullable=False, default=0)
    uptime = Column(Float, nullable=False)
    load_average = Column(Float, nullable=True)
    gpu_percent = Column(Float, nullable=True)
    gpu_mem_percent = Column(Float, nullable=True)
    temperature_c = Column(Float, nullable=True)

    device = db.relationship("PhysicalDevice", back_populates="telemetry")


class DeviceEvent(db.Model):
    """Audited asynchronous device lifecycle and security events."""

    __tablename__ = "device_events"
    __table_args__ = (Index("idx_device_events_device_occurred", "device_id", "occurred_at"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(
        Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type = Column(SQLEnum(DeviceEventType, native_enum=False), nullable=False, index=True)
    severity = Column(
        SQLEnum(EventSeverity, native_enum=False), nullable=False, default=EventSeverity.INFO
    )
    payload = Column(JSON, nullable=False, default=dict)
    occurred_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)

    device = db.relationship("PhysicalDevice", back_populates="events")


class ProcessedEvent(db.Model):
    """Server-side idempotency record tracking processed event IDs per device."""

    __tablename__ = "processed_events"
    __table_args__ = (
        db.UniqueConstraint("device_id", "event_id", name="uq_processed_events_device_event"),
        Index("idx_processed_events_device_time", "device_id", "processed_at"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(
        Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id = Column(String(64), nullable=False, index=True)
    processed_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
