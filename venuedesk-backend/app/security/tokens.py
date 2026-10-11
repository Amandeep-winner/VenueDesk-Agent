"""Pairing token generation, hashing, and atomic consumption."""
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.extensions import db
from app.models import EnrollmentToken, EnrollmentTokenStatus


def generate_pairing_token() -> str:
    """Generate high-entropy asset-scoped pairing token (PAIR-...)."""
    return f"PAIR-{secrets.token_urlsafe(32)}"


def hash_token(raw_token: str) -> str:
    """Calculate SHA-256 hex digest of raw pairing token."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def create_token_for_asset(asset_id: int, created_by: str = "admin", ttl_hours: int = 24) -> tuple[str, EnrollmentToken]:
    """Generate and store pairing token for an asset, revoking prior active tokens."""
    # Revoke any prior active tokens for this asset
    prior_tokens = EnrollmentToken.query.filter_by(
        asset_id=asset_id,
        status=EnrollmentTokenStatus.ACTIVE
    ).all()
    for tok in prior_tokens:
        tok.status = EnrollmentTokenStatus.REVOKED
        tok.revoked_at = datetime.now(UTC)

    raw_token = generate_pairing_token()
    token_obj = EnrollmentToken(
        asset_id=asset_id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
        created_by=created_by,
        status=EnrollmentTokenStatus.ACTIVE
    )
    db.session.add(token_obj)
    db.session.flush()
    return raw_token, token_obj


def consume_token_atomically(raw_token: str, device_id: int | None = None) -> EnrollmentToken:
    """Atomically validate and mark pairing token as USED within current transaction."""
    thash = hash_token(raw_token)
    now = datetime.now(UTC)

    # Use SELECT FOR UPDATE for concurrency safety
    token_row = db.session.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == thash).with_for_update()
    ).scalar_one_or_none()

    if token_row is None:
        raise ValueError("Invalid pairing token")

    if token_row.status != EnrollmentTokenStatus.ACTIVE:
        raise ValueError(f"Pairing token is not active (status: {token_row.status.value})")

    # Check expiry
    # Normalize token_row.expires_at to UTC
    expires_at = token_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if now > expires_at:
        token_row.status = EnrollmentTokenStatus.EXPIRED
        db.session.flush()
        raise ValueError("Pairing token has expired")

    token_row.status = EnrollmentTokenStatus.USED
    token_row.used_at = now
    if device_id is not None:
        token_row.used_by_device_id = device_id

    db.session.flush()
    return token_row
