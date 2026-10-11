"""Test fixtures for VenueDesk Agent."""
import pytest

from agent.config import AgentConfig


@pytest.fixture
def default_config(tmp_path):
    """Provide a standard agent config using temporary state directory."""
    return AgentConfig(
        server_url="http://127.0.0.1:5001",
        state_dir=str(tmp_path / "agent_state"),
        allow_insecure_dev=True
    )
