"""Unit tests for agent Ed25519 keys, keystores, and golden image safety."""
import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.config import AgentConfig
from agent.identity.keys import (
    FileKeyStore,
    TpmKeyStore,
    export_public_key_b64,
    generate_key,
    get_keystore,
    load_or_create_key,
    sign_message,
)


def test_ed25519_generation_and_export():
    key = generate_key()
    pub_b64 = export_public_key_b64(key)
    raw_pub = base64.b64decode(pub_b64)
    assert len(raw_pub) == 32

    # Verify public key object round-trip
    pub_obj = Ed25519PublicKey.from_public_bytes(raw_pub)
    assert export_public_key_b64(pub_obj) == pub_b64


def test_ed25519_sign_and_verify():
    key = generate_key()
    msg = b"GET\n/api/v1/agents/heartbeat\n1760000000\nnonce123\nabcdef"
    sig_b64 = sign_message(key, msg)

    raw_sig = base64.b64decode(sig_b64)
    assert len(raw_sig) == 64

    # Verification should succeed
    key.public_key().verify(raw_sig, msg)


def test_file_keystore_persistence_and_permissions(tmp_path):
    key_path = tmp_path / "keys" / "device_key.pem"
    store = FileKeyStore(key_path)

    assert store.load_key() is None

    key = generate_key()
    store.save_key(key)

    assert key_path.is_file()

    # Permissions on POSIX
    if sys.platform != "win32":
        mode = os.stat(key_path).st_mode & 0o777
        assert mode == 0o600

    loaded = store.load_key()
    assert loaded is not None
    assert export_public_key_b64(key) == export_public_key_b64(loaded)


def test_tpm_keystore_not_implemented():
    tpm = TpmKeyStore()
    with pytest.raises(NotImplementedError):
        tpm.load_key()
    key = generate_key()
    with pytest.raises(NotImplementedError):
        tpm.save_key(key)


def test_golden_image_safety_generates_unique_keys(tmp_path):
    """If state dir / key is absent (e.g. golden image deployment), a fresh key is generated."""
    dir1 = tmp_path / "endpoint_1"
    dir2 = tmp_path / "endpoint_2"

    cfg1 = AgentConfig(state_dir=str(dir1))
    cfg2 = AgentConfig(state_dir=str(dir2))

    store1 = get_keystore(cfg1)
    store2 = get_keystore(cfg2)

    key1 = load_or_create_key(store1)
    key2 = load_or_create_key(store2)

    # Two separate endpoints generating their keys on boot must have distinct keys
    assert export_public_key_b64(key1) != export_public_key_b64(key2)

    # Re-reading same store produces the persistent key
    key1_reload = load_or_create_key(store1)
    assert export_public_key_b64(key1) == export_public_key_b64(key1_reload)
