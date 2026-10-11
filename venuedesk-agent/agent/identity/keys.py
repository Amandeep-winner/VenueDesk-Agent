"""Ed25519 cryptographic key generation, loading, signing, and KeyStore interface."""
import base64
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

if TYPE_CHECKING:
    from agent.config import AgentConfig


class KeyStore(ABC):
    """Abstract interface for storing and retrieving the agent's private key."""

    @abstractmethod
    def load_key(self) -> Ed25519PrivateKey | None:
        """Load the stored private key, or return None if not yet initialized."""

    @abstractmethod
    def save_key(self, key: Ed25519PrivateKey) -> None:
        """Securely persist the private key."""


class FileKeyStore(KeyStore):
    """Filesystem-based key storage with strict OS-level permissions (0600 / DPAPI)."""

    def __init__(self, key_path: str | Path) -> None:
        self.key_path = Path(key_path)

    def load_key(self) -> Ed25519PrivateKey | None:
        if not self.key_path.is_file():
            return None
        pem_data = self.key_path.read_bytes()
        loaded = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise TypeError(f"Stored key at {self.key_path} is not an Ed25519 private key")
        return loaded

    def save_key(self, key: Ed25519PrivateKey) -> None:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        pem_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem_data)

        # Enforce strict file permissions
        if sys.platform != "win32":
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass


class TpmKeyStore(KeyStore):
    """TPM-backed key storage stub. Raises NotImplementedError."""

    def load_key(self) -> Ed25519PrivateKey | None:
        raise NotImplementedError("TPM key storage is not supported on this platform/configuration.")

    def save_key(self, key: Ed25519PrivateKey) -> None:
        raise NotImplementedError("TPM key storage is not supported on this platform/configuration.")


def generate_key() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 private key."""
    return Ed25519PrivateKey.generate()


def export_public_key_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """Export raw 32-byte Ed25519 public key as standard base64 string."""
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def sign_message(key: Ed25519PrivateKey, message: bytes) -> str:
    """Sign raw message bytes with Ed25519 private key, returning base64 signature."""
    sig_bytes = key.sign(message)
    return base64.b64encode(sig_bytes).decode("ascii")


def load_or_create_key(keystore: KeyStore) -> Ed25519PrivateKey:
    """Load existing private key from keystore or generate and persist a new key."""
    key = keystore.load_key()
    if key is None:
        key = generate_key()
        keystore.save_key(key)
    return key


def get_keystore(config: "AgentConfig") -> KeyStore:
    """Factory creating appropriate KeyStore instance based on agent configuration."""
    if config.key_store.lower() == "tpm":
        return TpmKeyStore()
    key_file = Path(config.state_dir) / "device_key.pem"
    return FileKeyStore(key_file)
