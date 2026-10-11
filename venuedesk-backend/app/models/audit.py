"""Audit log model for immutable tracking of all administrative and lifecycle operations."""
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy import Enum as SQLEnum

from app.extensions import db
from app.models.enums import ActorType, AuditAction


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class AuditLog(db.Model):
    """Append-only audit trail."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String(128), nullable=False)
    actor_type = Column(SQLEnum(ActorType, native_enum=False), nullable=False, default=ActorType.USER)
    action = Column(SQLEnum(AuditAction, native_enum=False), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False)
    entity_id = Column(String(128), nullable=False, index=True)
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    ip_address = Column(String(64), nullable=True)
    metadata_json = Column(JSON, nullable=True)
