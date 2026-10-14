"""Unit tests for agent retry policy, authenticated client, and heartbeat."""

from unittest.mock import patch

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.communication.client import AuthenticatedClient
from agent.communication.heartbeat import send_heartbeat
from agent.communication.retry import RetryPolicy
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.identity.keys import FileKeyStore, export_public_key_b64
from agent.storage.database import AgentDatabase


def test_retry_policy_delay_and_retry_after():
    policy = RetryPolicy(
        max_attempts=3,
        initial_interval=1.0,
        backoff_multiplier=2.0,
        jitter_factor=0.0,
    )
    # Attempt 1: 1.0s, Attempt 2: 2.0s
    assert policy.compute_delay(1) == 1.0
    assert policy.compute_delay(2) == 2.0

    # Response with Retry-After: 15
    resp = httpx.Response(429, headers={"Retry-After": "15"})
    assert policy.compute_delay(1, response=resp) == 15.0


def test_retry_policy_recovers_after_transient_failure():
    policy = RetryPolicy(max_attempts=3, initial_interval=0.01)
    call_count = 0

    def mock_call():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            return httpx.Response(500)
        return httpx.Response(200, json={"ok": True})

    resp = policy.execute(mock_call)
    assert resp.status_code == 200
    assert call_count == 2


def test_authenticated_client_headers_and_dispatch(tmp_path):
    cfg = AgentConfig(
        server_url="http://127.0.0.1:5001",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )
    db = AgentDatabase(tmp_path / "agent_state.db")
    id_store = IdentityStore(db)
    id_store.set_device_id("VD-DEVICE-TEST01")
    id_store.set_credential_version(1)

    key_store = FileKeyStore(tmp_path / "device_key.pem")
    priv_key = Ed25519PrivateKey.generate()
    key_store.save_key(priv_key)

    client = AuthenticatedClient(cfg, db=db, keystore=key_store)

    fake_resp = httpx.Response(
        200, json={"server_time": 1760000000, "config_version": 1, "pending_jobs": False}
    )
    with patch("httpx.Client.request", return_value=fake_resp) as mock_req:
        resp = client.post("/api/v1/agents/heartbeat", json_data={"status": "ACTIVE"})
        assert resp.status_code == 200
        assert mock_req.called

        _, kwargs = mock_req.call_args
        headers = kwargs["headers"]
        assert headers["X-Device-ID"] == "VD-DEVICE-TEST01"
        assert headers["X-Key-Version"] == "1"
        assert "X-Signature" in headers
        assert "X-Nonce" in headers
        assert "X-Timestamp" in headers


def test_send_heartbeat_updates_local_state(tmp_path):
    cfg = AgentConfig(
        server_url="http://127.0.0.1:5001",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )
    db = AgentDatabase(tmp_path / "agent_state.db")
    id_store = IdentityStore(db)
    id_store.set_device_id("VD-DEVICE-TEST01")

    key_store = FileKeyStore(tmp_path / "device_key.pem")
    key_store.save_key(Ed25519PrivateKey.generate())

    client = AuthenticatedClient(cfg, db=db, keystore=key_store)

    fake_resp = httpx.Response(
        200, json={"server_time": 1760000000, "config_version": 1, "pending_jobs": False}
    )
    with patch("httpx.Client.request", return_value=fake_resp):
        res = send_heartbeat(client)
        assert res["server_time"] == 1760000000

    last_hb = db.get_state("last_heartbeat")
    assert last_hb is not None


def test_client_rotate_credential(tmp_path):
    cfg = AgentConfig(
        server_url="http://127.0.0.1:5001",
        state_dir=str(tmp_path),
        allow_insecure_dev=True,
    )
    db = AgentDatabase(tmp_path / "agent_state.db")
    id_store = IdentityStore(db)
    id_store.set_device_id("VD-DEVICE-TEST01")
    id_store.set_credential_version(1)

    key_store = FileKeyStore(tmp_path / "device_key.pem")
    old_key = Ed25519PrivateKey.generate()
    key_store.save_key(old_key)
    old_pub = export_public_key_b64(old_key)

    client = AuthenticatedClient(cfg, db=db, keystore=key_store)

    fake_resp = httpx.Response(200, json={"status": "rotated", "credential_version": 2})
    with patch("httpx.Client.request", return_value=fake_resp):
        res = client.rotate_credential()
        assert res["credential_version"] == 2

    # Verifications: DB version bumped, keystore updated with new key
    assert id_store.credential_version == 2
    new_loaded_key = key_store.load_key()
    assert export_public_key_b64(new_loaded_key) != old_pub
