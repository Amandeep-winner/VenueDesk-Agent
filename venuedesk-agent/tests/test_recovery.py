"""Unit tests for agent-side recovery client and CLI command."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent.communication.recovery import recover_agent
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.main import cli
from agent.storage.database import AgentDatabase


def test_recover_agent_refuses_insecure_url(tmp_path):
    cfg = AgentConfig(
        server_url="http://insecure.internal",
        state_dir=str(tmp_path),
        allow_insecure_dev=False,
    )
    with pytest.raises(ValueError, match="Insecure HTTP"):
        recover_agent(cfg)


def test_recover_agent_success_no_wait(tmp_path):
    cfg = AgentConfig(
        server_url="http://localhost:5000",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )

    fake_post_resp = MagicMock()
    fake_post_resp.status_code = 200
    fake_post_resp.json.return_value = {
        "status": "pending_approval",
        "device_id": "VD-DEVICE-REC12345",
        "recovery_request_id": 1,
    }

    with patch("httpx.Client.post", return_value=fake_post_resp) as mock_post:
        res = recover_agent(cfg, wait_for_approval=False)
        assert res["status"] == "pending_approval"
        assert res["device_id"] == "VD-DEVICE-REC12345"
        assert mock_post.called


def test_recover_agent_with_wait_polling_success(tmp_path):
    cfg = AgentConfig(
        server_url="http://localhost:5000",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )

    fake_post_resp = MagicMock()
    fake_post_resp.status_code = 200
    fake_post_resp.json.return_value = {
        "status": "pending_approval",
        "device_id": "VD-DEVICE-REC12345",
        "recovery_request_id": 1,
    }

    fake_poll_pending = MagicMock(status_code=200)
    fake_poll_pending.json.return_value = {"status": "pending"}

    fake_poll_approved = MagicMock(status_code=200)
    fake_poll_approved.json.return_value = {
        "status": "approved",
        "device_id": "VD-DEVICE-REC12345",
        "credential_version": 2,
    }

    with (
        patch("httpx.Client.post", return_value=fake_post_resp),
        patch("httpx.Client.get", side_effect=[fake_poll_pending, fake_poll_approved]),
        patch("time.sleep"),
    ):
        res = recover_agent(cfg, wait_for_approval=True, poll_timeout_seconds=5, poll_interval=0.01)
        assert res["status"] == "approved"
        assert res["credential_version"] == 2

    # Check local identity store was updated
    db = AgentDatabase(tmp_path / "agent_state.db")
    id_store = IdentityStore(db)
    assert id_store.device_id == "VD-DEVICE-REC12345"
    assert id_store.credential_version == 2


def test_recover_agent_with_wait_rejected(tmp_path):
    cfg = AgentConfig(
        server_url="http://localhost:5000",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )

    fake_post_resp = MagicMock()
    fake_post_resp.status_code = 200
    fake_post_resp.json.return_value = {
        "status": "pending_approval",
        "device_id": "VD-DEVICE-REC12345",
    }

    fake_poll_rejected = MagicMock(status_code=200)
    fake_poll_rejected.json.return_value = {"status": "rejected"}

    with (
        patch("httpx.Client.post", return_value=fake_post_resp),
        patch("httpx.Client.get", return_value=fake_poll_rejected),
        patch("time.sleep"),
        pytest.raises(RuntimeError, match="rejected by administrator"),
    ):
        recover_agent(cfg, wait_for_approval=True, poll_timeout_seconds=5)


def test_recover_cli_command(tmp_path):
    runner = CliRunner()
    cfg_file = tmp_path / "config.toml"
    state_dir_str = str(tmp_path).replace("\\", "/")
    cfg_file.write_text(f"""
server_url = "http://localhost:5000"
state_dir = "{state_dir_str}"
allow_insecure_dev = true
""")

    fake_post_resp = MagicMock(status_code=200)
    fake_post_resp.json.return_value = {
        "status": "pending_approval",
        "device_id": "VD-DEVICE-CLI-REC",
    }

    with patch("httpx.Client.post", return_value=fake_post_resp):
        res = runner.invoke(cli, ["--config", str(cfg_file), "recover"])
        assert res.exit_code == 0
        assert "VD-DEVICE-CLI-REC" in res.output
        assert "pending_approval" in res.output
