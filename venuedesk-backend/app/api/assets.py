"""Admin asset and pairing token management endpoints."""
from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AuditAction,
    AuditLog,
    EnrollmentToken,
    EnrollmentTokenStatus,
)
from app.security.rbac import require_admin
from app.security.tokens import create_token_for_asset

assets_bp = Blueprint("assets", __name__, url_prefix="/api/v1/admin/assets")


def _find_asset(asset_identifier: str) -> Asset | None:
    """Find asset by asset_id (VD-ASSET-...) or primary key id."""
    asset = Asset.query.filter_by(asset_id=asset_identifier).first()
    if asset:
        return asset
    try:
        pk_id = int(asset_identifier)
        return db.session.get(Asset, pk_id)
    except ValueError:
        return None


@assets_bp.route("/<asset_id>/pairing-token", methods=["POST"])
@require_admin
def generate_pairing_token_endpoint(asset_id: str):
    """Generate a single-use, 24h pairing token for the asset, revoking prior active tokens."""
    asset = _find_asset(asset_id)
    if not asset:
        return jsonify({"error": "not_found", "message": f"Asset {asset_id} not found"}), 404

    current_user = getattr(g, "current_user", None)
    admin_name = current_user.username if current_user else "admin"

    ttl_hours = 24
    if request.is_json and request.json and "ttl_hours" in request.json:
        try:
            ttl_hours = int(request.json["ttl_hours"])
        except (ValueError, TypeError):
            pass

    raw_token, token_obj = create_token_for_asset(asset.id, created_by=admin_name, ttl_hours=ttl_hours)

    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.TOKEN_CREATED,
            entity_type="asset",
            entity_id=asset.asset_id,
            new_value={"expires_at": token_obj.expires_at.isoformat()},
        )
    )
    db.session.commit()

    return jsonify({
        "asset_id": asset.asset_id,
        "token": raw_token,
        "expires_at": token_obj.expires_at.isoformat(),
    }), 201


@assets_bp.route("/<asset_id>/pairing-token", methods=["DELETE"])
@require_admin
def revoke_pairing_token_endpoint(asset_id: str):
    """Revoke any active pairing tokens for this asset."""
    asset = _find_asset(asset_id)
    if not asset:
        return jsonify({"error": "not_found", "message": f"Asset {asset_id} not found"}), 404

    current_user = getattr(g, "current_user", None)
    admin_name = current_user.username if current_user else "admin"

    active_tokens = EnrollmentToken.query.filter_by(
        asset_id=asset.id,
        status=EnrollmentTokenStatus.ACTIVE,
    ).all()

    revoked_count = 0
    now = datetime.now(UTC)
    for tok in active_tokens:
        tok.status = EnrollmentTokenStatus.REVOKED
        tok.revoked_at = now
        revoked_count += 1

    if revoked_count > 0:
        db.session.add(
            AuditLog(
                actor_id=admin_name,
                actor_type=ActorType.USER,
                action=AuditAction.TOKEN_REVOKED,
                entity_type="asset",
                entity_id=asset.asset_id,
                metadata_json={"revoked_count": revoked_count},
            )
        )
        db.session.commit()

    return jsonify({
        "status": "revoked",
        "asset_id": asset.asset_id,
        "revoked_count": revoked_count,
    }), 200
