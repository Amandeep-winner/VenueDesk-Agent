"""Enrollment token model."""
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import EnrollmentTokenStatus


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class EnrollmentToken(db.Model):
    """Single-use, short-lived, asset-scoped pairing token."""
    __tablename__ = "enrollment_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    used_by_device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="SET NULL"), nullable=True)
    created_by = Column(String(128), nullable=False, default="admin")
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(
        SQLEnum(EnrollmentTokenStatus, native_enum=False),
        nullable=False,
        default=EnrollmentTokenStatus.ACTIVE
    )

    asset = db.relationship("Asset", back_populates="tokens")
    used_by_device = db.relationship("PhysicalDevice")
