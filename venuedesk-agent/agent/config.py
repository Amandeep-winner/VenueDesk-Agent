"""Agent configuration loader supporting config.toml and VENUEDESK_ env vars."""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AgentConfig:
    """Agent runtime configuration settings."""

    server_url: str = "https://127.0.0.1:5001"
    deployment_salt: bytes = b"venuedesk-default-salt-32-chars-long!"
    heartbeat_seconds: int = 60
    telemetry_seconds: int = 60
    inventory_seconds: int = 21600
    jobs_poll_seconds: int = 60
    outbox_max_items: int = 10000
    outbox_ttl_hours: int = 24
    key_store: str = "file"
    approved_services: list[str] = field(default_factory=list)
    diagnostic_allowlist: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allow_insecure_dev: bool = False
    auto_update: bool = False  # Default notify-only safe update policy
    agent_version: str = "0.1.0"
    log_level: str = "INFO"
    state_dir: str = "data"

    def validate_server_url(self) -> None:
        """Validate secure server configuration and reject insecure HTTP without dev bypass."""
        if self.server_url and self.server_url.startswith("http://"):
            if not self.allow_insecure_dev:
                raise ValueError(
                    "Insecure HTTP server URLs are rejected unless allow_insecure_dev is true."
                )
            import logging

            logging.getLogger(__name__).warning(
                "LOUD WARNING: Insecure unencrypted HTTP connection permitted to '%s' because "
                "allow_insecure_dev=True. Never use unencrypted HTTP in production!",
                self.server_url,
            )

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "AgentConfig":
        """Load configuration from config.toml and environment variables."""
        cfg_dict: dict = {}

        # Look for explicit or default config path
        candidate_paths = (
            [config_path]
            if config_path
            else [
                Path("config.toml"),
                Path("venuedesk-agent/config.toml"),
                Path.home() / ".config" / "venuedesk" / "config.toml",
            ]
        )

        for path in candidate_paths:
            if path and Path(path).is_file():
                with open(path, "rb") as f:
                    cfg_dict = tomllib.load(f)
                break

        # Override from environment variables (VENUEDESK_*)
        def get_env(name: str, default: Any | None = None) -> Any:
            return os.getenv(f"VENUEDESK_{name.upper()}", default)

        server_url = get_env("server_url", cfg_dict.get("server_url", "https://127.0.0.1:5001"))
        raw_salt = get_env(
            "deployment_salt",
            cfg_dict.get("deployment_salt", "venuedesk-default-salt-32-chars-long!"),
        )
        salt = raw_salt.encode("utf-8") if isinstance(raw_salt, str) else raw_salt

        heartbeat = int(get_env("heartbeat_seconds", cfg_dict.get("heartbeat_seconds", 60)))
        telemetry = int(get_env("telemetry_seconds", cfg_dict.get("telemetry_seconds", 60)))
        inventory = int(get_env("inventory_seconds", cfg_dict.get("inventory_seconds", 21600)))
        jobs_poll = int(get_env("jobs_poll_seconds", cfg_dict.get("jobs_poll_seconds", 60)))
        outbox_max = int(get_env("outbox_max_items", cfg_dict.get("outbox_max_items", 10000)))
        outbox_ttl = int(get_env("outbox_ttl_hours", cfg_dict.get("outbox_ttl_hours", 24)))
        key_store = get_env("key_store", cfg_dict.get("key_store", "file"))
        approved_services = cfg_dict.get("approved_services", [])
        diag_allowlist = cfg_dict.get("diagnostic_allowlist", ["127.0.0.1", "localhost"])

        allow_insecure = get_env("allow_insecure_dev", cfg_dict.get("allow_insecure_dev", False))
        if isinstance(allow_insecure, str):
            allow_insecure = allow_insecure.lower() in ("true", "1", "yes")

        auto_update = get_env("auto_update", cfg_dict.get("auto_update", False))
        if isinstance(auto_update, str):
            auto_update = auto_update.lower() in ("true", "1", "yes")

        agent_version = get_env("agent_version", cfg_dict.get("agent_version", "0.1.0"))
        log_level = get_env("log_level", cfg_dict.get("log_level", "INFO"))
        state_dir = get_env("state_dir", cfg_dict.get("state_dir", "data"))

        return cls(
            server_url=server_url,
            deployment_salt=salt,
            heartbeat_seconds=heartbeat,
            telemetry_seconds=telemetry,
            inventory_seconds=inventory,
            jobs_poll_seconds=jobs_poll,
            outbox_max_items=outbox_max,
            outbox_ttl_hours=outbox_ttl,
            key_store=key_store,
            approved_services=approved_services,
            diagnostic_allowlist=diag_allowlist,
            allow_insecure_dev=allow_insecure,
            auto_update=auto_update,
            agent_version=agent_version,
            log_level=log_level,
            state_dir=state_dir,
        )
