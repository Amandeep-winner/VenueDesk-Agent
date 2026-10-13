"""Smoke and unit tests for agent configuration and CLI."""

from click.testing import CliRunner

from agent.config import AgentConfig
from agent.logging_setup import RedactingFilter
from agent.main import cli


def test_agent_config_defaults():
    """Verify default configuration values."""
    cfg = AgentConfig()
    assert cfg.heartbeat_seconds == 60
    assert cfg.telemetry_seconds == 60
    assert cfg.outbox_max_items == 10000
    assert cfg.key_store == "file"
    assert cfg.allow_insecure_dev is False


def test_log_redaction():
    """Verify pairing tokens are redacted from log messages."""
    raw = "Attempting enrollment with token PAIR-abc123XYZ_456789 to server"
    redacted = RedactingFilter.redact(raw)
    assert "PAIR-[REDACTED]" in redacted
    assert "PAIR-abc123XYZ_456789" not in redacted


def test_cli_help():
    """Verify CLI help executes cleanly."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "VenueDesk Endpoint Agent CLI" in result.output
