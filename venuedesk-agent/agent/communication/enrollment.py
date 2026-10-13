"""Agent enrollment client implementation."""

import hashlib
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
    load_or_create_key,
    sign_message,
)
from agent.storage.database import AgentDatabase


def enroll_agent(
    config: AgentConfig,
    token: str | None = None,
    force_reenroll: bool = False,
    server_url: str | None = None,
) -> dict:
    """Enroll endpoint with the control plane and persist the assigned device identity."""
    server = (server_url or config.server_url).rstrip("/")
    if server.startswith("http://") and not config.allow_insecure_dev:
        raise ValueError(
            "Insecure HTTP server URLs are rejected unless allow_insecure_dev is true."
        )

    db_path = Path(config.state_dir) / "agent_state.db"
    db = AgentDatabase(db_path)
    id_store = IdentityStore(db)

    if id_store.is_enrolled() and not force_reenroll:
        raise RuntimeError(
            f"Endpoint is already enrolled with device_id {id_store.device_id}. Pass --force-reenroll to re-enroll."
        )

    keystore = get_keystore(config)
    if force_reenroll:
        key = generate_key()
        keystore.save_key(key)
    else:
        key = load_or_create_key(keystore)

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

    token_sha256 = hashlib.sha256(token.strip().encode("utf-8")).hexdigest() if token else ""
    ts = int(time.time())
    nonce = uuid.uuid4().hex

    proof_message = f"enroll\n{token_sha256}\n{ts}\n{nonce}".encode()
    pop_sig = sign_message(key, proof_message)

    payload = {
        "enrollment_token": token.strip() if token else None,
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
        response = client.post(f"{server}/api/v1/agents/enroll", json=payload)

    if response.status_code != 200:
        raise RuntimeError(f"Enrollment failed ({response.status_code}): {response.text}")

    result = response.json()
    id_store.set_device_id(result["device_id"])
    cred_ver = result.get("credential", {}).get("credential_version", 1)
    id_store.set_credential_version(cred_ver)

    return result
