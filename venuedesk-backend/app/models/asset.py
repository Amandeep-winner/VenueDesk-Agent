"""Asset models and race-safe asset identifier generator."""

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, select
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import AssetLifecycleStatus, AssetType, AssetVerificationStatus


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class AssetSequence(db.Model):
    """Sequence counter for generating sequential zero-padded asset IDs."""

    __tablename__ = "asset_sequences"

    id = Column(Integer, primary_key=True)
    next_val = Column(Integer, nullable=False, default=1)


class Asset(db.Model):
    """Institutional physical or virtual IT asset."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(String(32), unique=True, nullable=False, index=True)
    asset_tag = Column(String(64), unique=True, nullable=True, index=True)
    asset_type = Column(
        SQLEnum(AssetType, native_enum=False), nullable=False, default=AssetType.DESKTOP
    )
    department_id = Column(String(64), nullable=True)
    building_id = Column(String(64), nullable=True)
    room_id = Column(String(64), nullable=True)
    location_label = Column(String(128), nullable=True)
    position_label = Column(String(64), nullable=True)
    assigned_to = Column(String(128), nullable=True)
    purchase_date = Column(DateTime(timezone=True), nullable=True)
    warranty_end = Column(DateTime(timezone=True), nullable=True)
    lifecycle_status = Column(
        SQLEnum(AssetLifecycleStatus, native_enum=False),
        nullable=False,
        default=AssetLifecycleStatus.DRAFT,
    )
    verification_status = Column(
        SQLEnum(AssetVerificationStatus, native_enum=False),
        nullable=False,
        default=AssetVerificationStatus.UNVERIFIED,
    )
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    links = db.relationship("AssetDeviceLink", back_populates="asset", cascade="all, delete-orphan")
    tokens = db.relationship(
        "EnrollmentToken", back_populates="asset", cascade="all, delete-orphan"
    )


def generate_next_asset_id(session=None) -> str:
    """Generate next race-safe sequential asset ID in VD-ASSET-000001 format."""
    sess = session or db.session
    seq = sess.execute(select(AssetSequence).with_for_update()).scalar_one_or_none()

    if seq is None:
        seq = AssetSequence(id=1, next_val=1)
        sess.add(seq)
        sess.flush()

    current_val = seq.next_val
    seq.next_val += 1
    sess.flush()
    return f"VD-ASSET-{current_val:06d}"
