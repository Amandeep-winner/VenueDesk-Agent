"""Test fixtures for VenueDesk backend."""
import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def app():
    """Create test application configured for testing."""
    app = create_app(config_name="testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()
