"""Pairing token generation, hashing, and atomic consumption."""
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

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

    # Single atomic UPDATE statement across PostgreSQL and SQLite
    stmt = (
        db.update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == thash,
            EnrollmentToken.status == EnrollmentTokenStatus.ACTIVE,
            EnrollmentToken.expires_at > now,
            EnrollmentToken.revoked_at.is_(None),
        )
        .values(
            status=EnrollmentTokenStatus.USED,
            used_at=now,
            used_by_device_id=device_id,
        )
    )
    result = db.session.execute(stmt)
    if result.rowcount == 1:
        token_row = EnrollmentToken.query.filter_by(token_hash=thash).first()
        return token_row

    # When update affects 0 rows, reject with appropriate failure message
    tok = EnrollmentToken.query.filter_by(token_hash=thash).first()
    if tok is None:
        raise ValueError("Invalid pairing token")
    if tok.status != EnrollmentTokenStatus.ACTIVE:
        raise ValueError(f"Pairing token is not active (status: {tok.status.value})")

    expires_at = tok.expires_at if tok.expires_at.tzinfo else tok.expires_at.replace(tzinfo=UTC)
    if now > expires_at:
        tok.status = EnrollmentTokenStatus.EXPIRED
        db.session.flush()
        raise ValueError("Pairing token has expired")

    raise ValueError("Invalid pairing token")
