"""Role-based access control decorators for admin endpoints and server-rendered UI."""
import functools

from flask import flash, g, jsonify, redirect, request, session, url_for

from app.models import User, UserRole


def _authenticate_request() -> User | None:
    """Extract authenticated user from session or Basic auth."""
    user_id = session.get("user_id")
    if user_id:
        from app.extensions import db
        return db.session.get(User, user_id)
    if request.authorization:
        auth = request.authorization
        user = User.query.filter_by(username=auth.username).first()
        if user and user.check_password(auth.password):
            return user
    return None


def require_role(*allowed_roles: UserRole):
    """Decorator requiring administrative user session or API token with given roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = _authenticate_request()

            if not user:
                return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

            if allowed_roles and user.role not in allowed_roles:
                return jsonify({"error": "forbidden", "message": f"Requires role: {[r.value for r in allowed_roles]}"}), 403

            g.current_user = user
            return f(*args, **kwargs)

        return decorated
    return decorator


def require_admin(f):
    """Convenience decorator requiring infra_admin role."""
    return require_role(UserRole.INFRA_ADMIN)(f)


def require_ui_role(*allowed_roles: UserRole):
    """Decorator for server-rendered HTML UI requiring user session with proper roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = _authenticate_request()

            if not user:
                if request.is_json:
                    return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401
                return redirect(url_for("admin_infra.login", next=request.url))

            if allowed_roles and user.role not in allowed_roles:
                if request.is_json:
                    return jsonify({"error": "forbidden", "message": f"Requires role: {[r.value for r in allowed_roles]}"}), 403
                flash("Access denied: You do not have permissions for this action.", "danger")
                return redirect(url_for("admin_infra.devices_list"))

            g.current_user = user
            return f(*args, **kwargs)

        return decorated
    return decorator
