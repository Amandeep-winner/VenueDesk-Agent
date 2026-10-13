"""Configuration classes for VenueDesk Backend."""

import os


class BaseConfig:
    """Base configuration shared by all environments."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-in-prod")
    DEPLOYMENT_SALT = os.getenv("DEPLOYMENT_SALT", "venuedesk-default-salt-32-chars-long!").encode(
        "utf-8"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CLOCK_SKEW_SECONDS = int(os.getenv("CLOCK_SKEW_SECONDS", "120"))
    ENROLLMENT_TOKEN_TTL_HOURS = int(os.getenv("ENROLLMENT_TOKEN_TTL_HOURS", "24"))
    DUPLICATE_WINDOW_SECONDS = int(os.getenv("DUPLICATE_WINDOW_SECONDS", "120"))
    ALLOW_UNCLAIMED_ENROLLMENT = os.getenv("ALLOW_UNCLAIMED_ENROLLMENT", "false").lower() in (
        "true",
        "1",
        "yes",
    )
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
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PROXYFIX_ENABLED = True
    HSTS_ENABLED = True
    LOG_FORMAT = os.getenv("LOG_FORMAT", "json")
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "memory://")

    @classmethod
    def validate(cls):
        """Validate production prerequisites and fail fast if security requirements are missing."""
        secret = os.getenv("SECRET_KEY")
        if not secret or secret == "dev-insecure-secret-key-change-in-prod":
            raise ValueError(
                "Production configuration requires a strong, explicit SECRET_KEY environment variable."
            )

        salt = os.getenv("DEPLOYMENT_SALT")
        if not salt or salt == "venuedesk-default-salt-32-chars-long!":
            raise ValueError(
                "Production configuration requires a dedicated, non-default DEPLOYMENT_SALT environment variable."
            )

        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise ValueError(
                "Production configuration requires DATABASE_URL pointing to a production PostgreSQL database."
            )

        allow_sqlite = os.getenv("ALLOW_SQLITE_PROD", "false").lower() in ("true", "1", "yes")
        if db_url.startswith("sqlite") and not allow_sqlite:
            raise ValueError(
                "SQLite is not permitted in production. Configure a PostgreSQL DATABASE_URL or set ALLOW_SQLITE_PROD=true."
            )


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
