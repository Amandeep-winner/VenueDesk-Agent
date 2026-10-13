"""Backend API blueprint registration."""

from app.api.admin_infra import admin_infra_bp
from app.api.agents import agents_bp
from app.api.assets import assets_bp
from app.api.devices import devices_bp

__all__ = [
    "admin_infra_bp",
    "agents_bp",
    "assets_bp",
    "devices_bp",
]
