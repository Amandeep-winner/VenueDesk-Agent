"""Security primitives and authentication handlers."""
from app.security.rbac import require_admin, require_role
from app.security.replay import check_and_record_nonce, purge_expired_nonces
from app.security.signatures import canonical_string, require_device_auth, verify
from app.security.tokens import (
    consume_token_atomically,
    create_token_for_asset,
    generate_pairing_token,
    hash_token,
)

__all__ = [
    "canonical_string",
    "check_and_record_nonce",
    "consume_token_atomically",
    "create_token_for_asset",
    "generate_pairing_token",
    "hash_token",
    "purge_expired_nonces",
    "require_admin",
    "require_device_auth",
    "require_role",
    "verify",
]
