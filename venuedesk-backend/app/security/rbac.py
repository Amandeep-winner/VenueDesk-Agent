"""Role-based access control decorators for admin endpoints."""
import functools

from flask import g, jsonify, request, session

from app.models import User, UserRole


def require_role(*allowed_roles: UserRole):
    """Decorator requiring administrative user session or API token with given roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user_id = session.get("user_id")
            user = None
            if user_id:
                user = User.query.get(user_id)
            elif request.authorization:
                # Support Basic auth for API clients/testing
                auth = request.authorization
                user = User.query.filter_by(username=auth.username).first()
                if user and not user.check_password(auth.password):
                    user = None

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
