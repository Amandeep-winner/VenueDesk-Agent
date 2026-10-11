"""Authenticated HTTP client signing every request with the agent's Ed25519 key."""
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.communication.authentication import generate_auth_headers
from agent.communication.retry import RetryPolicy
from agent.config import AgentConfig
from agent.identity.device_id import IdentityStore
from agent.identity.keys import (
    KeyStore,
    export_public_key_b64,
    generate_key,
    get_keystore,
    sign_message,
)
from agent.storage.database import AgentDatabase


class AuthenticatedClient:
    """Client for device-authenticated communication with the VenueDesk control plane."""

    def __init__(
        self,
        config: AgentConfig,
        db: AgentDatabase | None = None,
        keystore: KeyStore | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.config = config
        self.server_url = config.server_url.rstrip("/")
        if self.server_url.startswith("http://") and not config.allow_insecure_dev:
            raise ValueError("Insecure HTTP server URLs are rejected unless allow_insecure_dev is true.")

        db_path = Path(config.state_dir) / "agent_state.db"
        self.db = db or AgentDatabase(db_path)
        self.id_store = IdentityStore(self.db)
        self.keystore = keystore or get_keystore(config)
        self.retry_policy = retry_policy or RetryPolicy()

    def _get_key(self) -> Ed25519PrivateKey:
        key = self.keystore.load_key()
        if not key:
            raise RuntimeError("Device private key not found. Agent must enroll first.")
        return key

    def request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Sign and dispatch an HTTP request with retry handling."""
        device_id = self.id_store.device_id
        if not device_id:
            raise RuntimeError("Agent is not enrolled (missing device_id).")

        key = self._get_key()
        cred_version = self.id_store.credential_version

        # Build path with query string for canonical string calculation
        path_with_query = path
        if params:
            query = urlencode(params)
            path_with_query = f"{path}?{query}"

        # Serialize body to raw bytes
        body_bytes = b""
        headers = {}
        if json_data is not None:
            body_bytes = json.dumps(json_data, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        auth_headers = generate_auth_headers(
            device_id=device_id,
            private_key=key,
            credential_version=cred_version,
            method=method,
            path_with_query=path_with_query,
            body=body_bytes,
        )
        headers.update(auth_headers)

        full_url = f"{self.server_url}{path}"

        def do_call() -> httpx.Response:
            with httpx.Client(timeout=15.0) as http_client:
                return http_client.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    content=body_bytes if json_data is not None else None,
                    params=params,
                )

        return self.retry_policy.execute(do_call)

    def get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_data: dict[str, Any] | None = None) -> httpx.Response:
        return self.request("POST", path, json_data=json_data)

    def rotate_credential(self) -> dict[str, Any]:
        """Generate fresh key pair and request credential rotation from control plane."""
        old_key = self._get_key()
        new_key = generate_key()
        new_pub_b64 = export_public_key_b64(new_key)
        device_id = self.id_store.device_id
        if not device_id:
            raise RuntimeError("Cannot rotate credential: agent is not enrolled.")

        import time
        ts = int(time.time())
        rot_msg = f"rotate\n{device_id}\n{new_pub_b64}\n{ts}".encode()
        old_sig = sign_message(old_key, rot_msg)

        payload = {
            "new_public_key": new_pub_b64,
            "signature_by_old_key": old_sig,
            "timestamp": ts,
        }

        resp = self.post("/api/v1/agents/rotate-credential", json_data=payload)
        if resp.status_code != 200:
            raise RuntimeError(f"Credential rotation failed ({resp.status_code}): {resp.text}")

        data = resp.json()
        new_cred_ver = data.get("credential_version", self.id_store.credential_version + 1)

        # Save new key and version only after successful server confirmation
        self.keystore.save_key(new_key)
        self.id_store.set_credential_version(new_cred_ver)
        return data
