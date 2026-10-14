"""CSRF protection primitives for server-rendered admin interfaces."""

import hmac
import secrets
from functools import wraps

from flask import flash, redirect, request, session


def get_csrf_token() -> str:
    """Generate or retrieve CSRF token stored in administrator session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token: str | None) -> bool:
    """Validate submitted token against session token using constant-time comparison."""
    expected = session.get("_csrf_token")
    if not expected or not token:
        return False
    return hmac.compare_digest(expected, token)


def require_csrf(f):
    """Decorator validating CSRF token on mutating HTTP requests."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not validate_csrf_token(token):
                if request.is_json:
                    return {"error": "csrf_error", "message": "Invalid or missing CSRF token"}, 400
                flash(
                    "Security verification failed: invalid or expired CSRF token. Please retry.",
                    "danger",
                )
                target = request.referrer or "/admin/infrastructure/devices"
                return redirect(target, code=303)
        return f(*args, **kwargs)

    return decorated
