"""Physical device, hardware identity evidence, and OS installation models."""
import secrets
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import (
    DeviceStatus,
    EndpointType,
    OsFamily,
    OsInstallationStatus,
    RelationshipStatus,
    VerificationMethod,
)


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


def generate_device_id() -> str:
    """Generate random device ID in VD-DEVICE-XXXXXXXX format."""
    return f"VD-DEVICE-{secrets.token_hex(4).upper()}"


class PhysicalDevice(db.Model):
    """Observed physical endpoint host."""
    __tablename__ = "physical_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(32), unique=True, nullable=False, index=True)
    device_public_key = Column(Text, nullable=False)
    device_certificate = Column(Text, nullable=True)
    credential_version = Column(Integer, nullable=False, default=1)
    status = Column(
        SQLEnum(DeviceStatus, native_enum=False),
        nullable=False,
        default=DeviceStatus.ENROLLING
    )
    endpoint_type = Column(
        SQLEnum(EndpointType, native_enum=False),
        nullable=False,
        default=EndpointType.PHYSICAL
    )
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    links = db.relationship("AssetDeviceLink", back_populates="device", cascade="all, delete-orphan")
    evidence_snapshots = db.relationship("DeviceIdentityEvidence", back_populates="device", cascade="all, delete-orphan")
    os_installations = db.relationship("OSInstallation", back_populates="device", cascade="all, delete-orphan")
    inventory = db.relationship("DeviceInventory", back_populates="device", uselist=False, cascade="all, delete-orphan")
    telemetry = db.relationship("Telemetry", back_populates="device", cascade="all, delete-orphan")
    events = db.relationship("DeviceEvent", back_populates="device", cascade="all, delete-orphan")
    jobs = db.relationship("DeviceJob", back_populates="device", cascade="all, delete-orphan")


class AssetDeviceLink(db.Model):
    """Mapping between an institutional Asset and a PhysicalDevice."""
    __tablename__ = "asset_device_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_status = Column(
        SQLEnum(RelationshipStatus, native_enum=False),
        nullable=False,
        default=RelationshipStatus.ACTIVE
    )
    linked_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    unlinked_at = Column(DateTime(timezone=True), nullable=True)
    linked_by = Column(String(128), nullable=False, default="system")
    reason = Column(Text, nullable=True)
    verification_id = Column(Integer, ForeignKey("verifications.id", ondelete="SET NULL"), nullable=True)

    asset = db.relationship("Asset", back_populates="links")
    device = db.relationship("PhysicalDevice", back_populates="links")
    verification = db.relationship("Verification")


from sqlalchemy import event, select


@event.listens_for(AssetDeviceLink, "before_insert")
def validate_single_active_link(mapper, connection, target):
    """Enforce invariant: at most one ACTIVE link per asset and per device."""
    if target.relationship_status == RelationshipStatus.ACTIVE:
        existing_for_asset = connection.execute(
            select(AssetDeviceLink.id).where(
                AssetDeviceLink.asset_id == target.asset_id,
                AssetDeviceLink.relationship_status == RelationshipStatus.ACTIVE
            )
        ).scalar_one_or_none()
        if existing_for_asset is not None:
            raise ValueError(f"Asset ID {target.asset_id} already has an ACTIVE link")

        existing_for_device = connection.execute(
            select(AssetDeviceLink.id).where(
                AssetDeviceLink.device_id == target.device_id,
                AssetDeviceLink.relationship_status == RelationshipStatus.ACTIVE
            )
        ).scalar_one_or_none()
        if existing_for_device is not None:
            raise ValueError(f"Device ID {target.device_id} already has an ACTIVE link")


class DeviceIdentityEvidence(db.Model):
    """Append-only snapshots of hardware identity evidence."""
    __tablename__ = "device_identity_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    machine_uuid_hash = Column(String(64), nullable=True)
    bios_serial_hash = Column(String(64), nullable=True)
    motherboard_serial_hash = Column(String(64), nullable=True)
    cpu_signature = Column(String(128), nullable=True)
    gpu_signature = Column(String(256), nullable=True)
    disk_identity_hash = Column(String(64), nullable=True)
    network_identity_hash = Column(String(64), nullable=True)
    tpm_identity = Column(String(64), nullable=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    fingerprint_version = Column(Integer, nullable=False, default=1)
    captured_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    evidence_version = Column(Integer, nullable=False, default=1)
    trusted = Column(Boolean, nullable=False, default=False)

    device = db.relationship("PhysicalDevice", back_populates="evidence_snapshots")


class OSInstallation(db.Model):
    """Operating system installations observed on a physical host."""
    __tablename__ = "os_installations"
    __table_args__ = (
        UniqueConstraint("device_id", "os_family", "os_machine_id_hash", name="uq_device_os_installation"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    os_family = Column(SQLEnum(OsFamily, native_enum=False), nullable=False)
    os_name = Column(String(128), nullable=False)
    os_version = Column(String(64), nullable=False)
    architecture = Column(String(32), nullable=False)
    os_machine_id_hash = Column(String(64), nullable=False)
    agent_instance_id = Column(String(64), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    status = Column(
        SQLEnum(OsInstallationStatus, native_enum=False),
        nullable=False,
        default=OsInstallationStatus.ACTIVE
    )

    device = db.relationship("PhysicalDevice", back_populates="os_installations")


class DeviceInventory(db.Model):
    """Current-state technical inventory snapshot (agent is source of truth)."""
    __tablename__ = "device_inventory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    hostname = Column(String(256), nullable=False)
    ip_addresses = Column(JSON, nullable=False, default=list)
    mac_addresses = Column(JSON, nullable=False, default=list)
    cpu_model = Column(String(128), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    ram_total_mb = Column(Integer, nullable=True)
    gpus = Column(JSON, nullable=True, default=list)
    disks = Column(JSON, nullable=True, default=list)
    os_summary = Column(String(256), nullable=True)
    bios_version = Column(String(128), nullable=True)
    tpm_present = Column(Boolean, nullable=False, default=False)
    agent_version = Column(String(32), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    device = db.relationship("PhysicalDevice", back_populates="inventory")


class Verification(db.Model):
    """Audit record of device-to-asset physical verification."""
    __tablename__ = "verifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    verified_by = Column(String(128), nullable=False)
    verification_method = Column(
        SQLEnum(VerificationMethod, native_enum=False),
        nullable=False,
        default=VerificationMethod.ADMIN_CONFIRMATION
    )
    observed_asset_tag = Column(String(64), nullable=True)
    observed_serial = Column(String(128), nullable=True)
    observed_location = Column(String(128), nullable=True)
    notes = Column(Text, nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

    device = db.relationship("PhysicalDevice")


class DeviceRecoveryRequest(db.Model):
    """Pending recovery requests from reinstalled endpoints awaiting admin approval."""
    __tablename__ = "device_recovery_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("physical_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    new_public_key = Column(Text, nullable=False)
    new_agent_instance_id = Column(String(64), nullable=False)
    new_os_info = Column(JSON, nullable=True)
    new_inventory = Column(JSON, nullable=True)
    new_evidence = Column(JSON, nullable=True)
    status = Column(String(32), nullable=False, default="PENDING")  # PENDING, APPROVED, REJECTED
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(128), nullable=True)

    device = db.relationship("PhysicalDevice")

