"""Unit tests for agent-side enrollment client."""
from unittest.mock import MagicMock, patch

import pytest

from agent.communication.enrollment import enroll_agent
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.storage.database import AgentDatabase


def test_agent_refuses_insecure_server_by_default(tmp_path):
    cfg = AgentConfig(
        server_url="http://insecure-server.local",
        state_dir=str(tmp_path),
        allow_insecure_dev=False,
    )
    with pytest.raises(ValueError, match="Insecure HTTP"):
        enroll_agent(cfg, token="PAIR-test")


def test_agent_refuses_duplicate_enrollment_without_force(tmp_path):
    db_file = tmp_path / "agent_state.db"
    db = AgentDatabase(db_file)
    id_store = IdentityStore(db)
    id_store.set_device_id("VD-DEVICE-EXISTING")

    cfg = AgentConfig(
        server_url="https://secure-server.local",
        state_dir=str(tmp_path),
        allow_insecure_dev=False,
    )

    with pytest.raises(RuntimeError, match="already enrolled"):
        enroll_agent(cfg, token="PAIR-test", force_reenroll=False)


def test_agent_enrollment_success_persists_credentials(tmp_path):
    cfg = AgentConfig(
        server_url="http://localhost:5001",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "device_id": "VD-DEVICE-9999AAAA",
        "asset_id": "VD-ASSET-000001",
        "status": "PENDING_VERIFICATION",
        "credential": {"type": "public_key_registered", "credential_version": 2},
        "config": {"heartbeat_seconds": 60},
    }

    with patch("httpx.Client.post", return_value=fake_response) as mock_post:
        res = enroll_agent(cfg, token="PAIR-valid-token")
        assert res["device_id"] == "VD-DEVICE-9999AAAA"
        assert mock_post.called

    # Verify persisted in database
    db_file = tmp_path / "agent_state.db"
    db = AgentDatabase(db_file)
    id_store = IdentityStore(db)
    assert id_store.device_id == "VD-DEVICE-9999AAAA"
    assert id_store.credential_version == 2


def test_agent_force_reenrollment(tmp_path):
    db_file = tmp_path / "agent_state.db"
    db = AgentDatabase(db_file)
    id_store = IdentityStore(db)
    id_store.set_device_id("VD-DEVICE-OLD")

    cfg = AgentConfig(
        server_url="http://localhost:5001",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "device_id": "VD-DEVICE-NEW",
        "status": "PENDING_VERIFICATION",
        "credential": {"type": "public_key_registered", "credential_version": 1},
    }

    with patch("httpx.Client.post", return_value=fake_response):
        res = enroll_agent(cfg, token="PAIR-new-token", force_reenroll=True)
        assert res["device_id"] == "VD-DEVICE-NEW"

    assert id_store.device_id == "VD-DEVICE-NEW"
