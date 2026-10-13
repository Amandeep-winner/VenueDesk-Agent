"""Configuration classes for VenueDesk Backend."""
import os


class BaseConfig:
    """Base configuration shared by all environments."""
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-in-prod")
    DEPLOYMENT_SALT = os.getenv("DEPLOYMENT_SALT", "venuedesk-default-salt-32-chars-long!").encode("utf-8")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "120"))
    ENROLLMENT_TOKEN_TTL_HOURS = int(os.getenv("ENROLLMENT_TOKEN_TTL_HOURS", "24"))
    DUPLICATE_WINDOW_SECONDS = int(os.getenv("DUPLICATE_WINDOW_SECONDS", "120"))
    ALLOW_UNCLAIMED_ENROLLMENT = os.getenv("ALLOW_UNCLAIMED_ENROLLMENT", "false").lower() in ("true", "1", "yes")
    SESSION_COOKIE_HTTPONLY = True
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB max payload


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///venuedesk_dev.db")


class TestingConfig(BaseConfig):
    """Testing environment configuration using in-memory SQLite or TEST_DATABASE_URL."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    ALLOW_UNCLAIMED_ENROLLMENT = False


class ProductionConfig(BaseConfig):
    """Production configuration requiring explicit environment settings."""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
