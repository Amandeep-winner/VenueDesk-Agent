"""Application factory for VenueDesk Control Plane Backend."""
import os

from flask import Flask, jsonify

import app.models  # noqa: F401
from app.config import config_by_name
from app.extensions import db, migrate
from app.security.csrf import get_csrf_token


def create_app(config_name=None):
    """Create and configure the Flask application instance."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    flask_app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    flask_app.config.from_object(config_obj)

    # Initialize extensions
    db.init_app(flask_app)
    migrate.init_app(flask_app, db)

    # Register Jinja global helpers
    flask_app.jinja_env.globals["csrf_token"] = get_csrf_token
    flask_app.jinja_env.globals["hasattr"] = hasattr

    # Health check route
    @flask_app.route("/healthz", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "ok",
            "service": "venuedesk-backend",
            "version": "0.1.0",
        }), 200

    # Register Blueprints
    from app.api.admin_infra import admin_infra_bp
    from app.api.agents import agents_bp
    from app.api.assets import assets_bp
    from app.api.devices import devices_bp
    flask_app.register_blueprint(agents_bp)
    flask_app.register_blueprint(assets_bp)
    flask_app.register_blueprint(devices_bp)
    flask_app.register_blueprint(admin_infra_bp)

    from app.cli import register_cli_commands
    register_cli_commands(flask_app)

    return flask_app
