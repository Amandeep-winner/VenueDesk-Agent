"""Remote diagnostic and maintenance job models."""

from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import JobStatus, JobType


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class DeviceJob(db.Model):
    """Allowlisted remote diagnostic or maintenance job dispatch."""

    __tablename__ = "device_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(
        Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_type = Column(SQLEnum(JobType, native_enum=False), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    status = Column(
        SQLEnum(JobStatus, native_enum=False), nullable=False, default=JobStatus.PENDING, index=True
    )
    created_by = Column(String(128), nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    result = Column(JSON, nullable=True)

    device = db.relationship("PhysicalDevice", back_populates="jobs")
