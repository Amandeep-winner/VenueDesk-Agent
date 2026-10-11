"""Application factory for VenueDesk Control Plane Backend."""
import os

from flask import Flask, jsonify

from app.config import config_by_name
from app.extensions import db, migrate


def create_app(config_name=None):
    """Create and configure the Flask application instance."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Health check route
    @app.route("/healthz", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "ok",
            "service": "venuedesk-backend",
            "version": "0.1.0"
        }), 200

    return app
