"""Agent endpoint recovery client implementation (spec §4.8)."""

import logging
import platform
import time
import uuid
from pathlib import Path

import httpx

from agent.collectors import collect_identity_evidence
from agent.collectors.system import collect_os_info
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.identity.keys import (
    export_public_key_b64,
    generate_key,
    get_keystore,
    sign_message,
)
from agent.storage.database import AgentDatabase

logger = logging.getLogger(__name__)


def recover_agent(
    config: AgentConfig,
    server_url: str | None = None,
    wait_for_approval: bool = False,
    poll_timeout_seconds: int = 60,
    poll_interval: float = 2.0,
) -> dict:
    """Submit endpoint recovery request following OS reinstall or state loss, and optionally poll for approval."""
    server = (server_url or config.server_url).rstrip("/")
    if server.startswith("http://") and not config.allow_insecure_dev:
        raise ValueError(
            "Insecure HTTP server URLs are rejected unless allow_insecure_dev is true."
        )

    db_path = Path(config.state_dir) / "agent_state.db"
    db = AgentDatabase(db_path)
    id_store = IdentityStore(db)

    keystore = get_keystore(config)
    key = generate_key()
    keystore.save_key(key)
    pub_key_b64 = export_public_key_b64(key)

    evidence = collect_identity_evidence()
    evidence_payload = evidence.to_evidence_payload(config.deployment_salt)
    os_info = collect_os_info()

    inventory = {
        "hostname": platform.node(),
        "ip_addresses": [],
        "mac_addresses": evidence.nics,
        "cpu_model": evidence.cpu,
        "gpus": evidence.gpus,
        "disks": evidence.disks,
        "os_summary": f"{os_info['name']} {os_info['version']}",
    }

    ts = int(time.time())
    nonce = uuid.uuid4().hex

    proof_message = f"recover\n{pub_key_b64}\n{ts}\n{nonce}".encode()
    pop_sig = sign_message(key, proof_message)

    payload = {
        "device_public_key": pub_key_b64,
        "proof_of_possession": pop_sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": evidence_payload,
        "inventory": inventory,
        "os": os_info,
        "agent_version": "0.1.0",
        "agent_instance_id": id_store.agent_instance_id,
        "os_installation_id": id_store.os_installation_id,
    }

    with httpx.Client(timeout=15.0) as client:
        response = client.post(f"{server}/api/v1/agents/recover", json=payload)

    if response.status_code != 200:
        raise RuntimeError(f"Recovery request failed ({response.status_code}): {response.text}")

    result = response.json()
    device_id = result.get("device_id")
    if not device_id:
        raise RuntimeError("No device_id returned in recovery response")

    if not wait_for_approval:
        return result

    start_time = time.time()
    logger.info("Waiting for admin approval of recovery for device %s...", device_id)
    with httpx.Client(timeout=10.0) as client:
        while time.time() - start_time < poll_timeout_seconds:
            status_resp = client.get(
                f"{server}/api/v1/agents/recover/status", params={"device_id": device_id}
            )
            if status_resp.status_code == 200:
                data = status_resp.json()
                if data.get("status") == "approved":
                    id_store.set_device_id(device_id)
                    cred_ver = data.get("credential_version", 1)
                    id_store.set_credential_version(cred_ver)
                    result["status"] = "approved"
                    result["credential_version"] = cred_ver
                    return result
                if data.get("status") == "rejected":
                    raise RuntimeError("Recovery request was rejected by administrator.")
            time.sleep(poll_interval)

    raise TimeoutError(f"Recovery approval timed out after {poll_timeout_seconds} seconds.")
