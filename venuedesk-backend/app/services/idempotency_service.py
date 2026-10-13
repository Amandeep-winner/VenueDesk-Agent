"""Server-side idempotency service tracking processed event IDs per device."""
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.telemetry import ProcessedEvent

logger = logging.getLogger(__name__)


def is_event_processed(device_id: int, event_id: str) -> bool:
    """Check if an event ID has already been recorded for this device."""
    if not event_id:
        return False
    return (
        db.session.query(ProcessedEvent)
        .filter_by(device_id=device_id, event_id=event_id)
        .first()
        is not None
    )


def record_processed_event(device_id: int, event_id: str) -> bool:
    """Record a processed event ID. Return True if new, False if already processed (duplicate)."""
    if not event_id:
        return True

    # Check existence first
    if is_event_processed(device_id, event_id):
        return False

    try:
        pe = ProcessedEvent(
            device_id=device_id,
            event_id=event_id,
            processed_at=datetime.now(UTC),
        )
        db.session.add(pe)
        db.session.flush()
        return True
    except IntegrityError:
        db.session.rollback()
        return False


def record_processed_events_batch(
    device_id: int,
    event_ids: list[str],
) -> tuple[list[str], list[str]]:
    """Record a batch of event IDs. Return (accepted_ids, duplicate_ids)."""
    accepted: list[str] = []
    duplicates: list[str] = []

    for eid in event_ids:
        if not eid:
            continue
        try:
            with db.session.begin_nested():
                pe = ProcessedEvent(
                    device_id=device_id,
                    event_id=eid,
                    processed_at=datetime.now(UTC),
                )
                db.session.add(pe)
                db.session.flush()
            accepted.append(eid)
        except IntegrityError:
            duplicates.append(eid)

    return accepted, duplicates


def purge_processed_events(older_than_seconds: int = 86400 * 2) -> int:
    """Purge processed event records older than the specified retention threshold."""
    cutoff = datetime.now(UTC) - timedelta(seconds=older_than_seconds)
    deleted = (
        db.session.query(ProcessedEvent)
        .filter(ProcessedEvent.processed_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.session.commit()
    logger.info("Purged %d expired processed_events records", deleted)
    return deleted
