"""Nonce validation and replay defense."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import RequestNonce


def check_and_record_nonce(device_id: str, nonce: str, skew_seconds: int = 120) -> bool:
    """Atomically verify nonce has not been seen for device, recording it if fresh."""
    now = datetime.now(UTC)

    # Opportunistically purge expired nonces occasionally
    purge_expired_nonces()

    existing = db.session.execute(
        select(RequestNonce.id).where(
            RequestNonce.device_id == device_id,
            RequestNonce.nonce == nonce
        )
    ).scalar_one_or_none()

    if existing is not None:
        return False

    new_nonce = RequestNonce(
        device_id=device_id,
        nonce=nonce,
        expires_at=now + timedelta(seconds=2 * skew_seconds)
    )
    db.session.add(new_nonce)
    try:
        db.session.flush()
        return True
    except IntegrityError:
        db.session.rollback()
        return False


def purge_expired_nonces() -> int:
    """Purge nonces that have passed their expiration timestamp."""
    now = datetime.now(UTC)
    result = RequestNonce.query.filter(RequestNonce.expires_at < now).delete(synchronize_session=False)
    db.session.flush()
    return result
