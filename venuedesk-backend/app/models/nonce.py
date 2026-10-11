"""Request replay defense nonce tracking model."""
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint

from app.extensions import db


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class RequestNonce(db.Model):
    """Replay defense nonce record per device within clock skew window."""
    __tablename__ = "request_nonces"
    __table_args__ = (
        UniqueConstraint("device_id", "nonce", name="uq_device_nonce"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(32), nullable=False, index=True)
    nonce = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
