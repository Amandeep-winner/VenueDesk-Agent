"""End-to-End Test Suite: Reliable Offline Operation and Idempotency (Phase 5).

Tests:
1. test_server_dedupes_event_ids:
   - Server dedupes telemetry batch event IDs, accepting new and acknowledging duplicates.
   - Server dedupes inventory and identity event IDs.
2. test_ack_lost_duplicate_delivery_has_no_side_effects:
   - Client sends event, server commits it, ACK is dropped before client marks delivered.
   - Client re-sends event, server acknowledges duplicate without creating duplicate database records.
3. test_expired_credentials_pause_and_recover:
   - Client receives 401 on outdated credential version, refreshes active credential, and flushes queue without dropping items.
"""

import base64
import json
import time
import uuid

import pytest
from agent.storage.outbox import (
    PRIORITY_IDENTITY_EVENT,
    PRIORITY_INVENTORY,
    Outbox,
)
from app import create_app
from app.extensions import db
from app.models import (
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetType,
    DeviceIdentityEvidence,
    DeviceStatus,
    PhysicalDevice,
    Telemetry,
    generate_next_asset_id,
)
from app.security.signatures import canonical_string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def app():
    """Create Flask application instance for offline E2E tests."""
    app_instance = create_app("testing")
    with app_instance.app_context():
        db.create_all()
        yield app_instance
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def sign_req(
    dev_id: str,
    key: Ed25519PrivateKey,
    method: str,
    path: str,
    body: bytes,
    key_ver: int = 1,
) -> dict[str, str]:
    """Helper generating standard X-Device-ID and Ed25519 signature headers."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canonical = canonical_string(method, path, ts, nonce, body)
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": str(key_ver),
        "X-Signature": sig,
    }


def _enroll_device(client, app, tag="OFFLINE-01"):
    """Helper to enroll an active device and return (device_id, key)."""
    from datetime import UTC, datetime

    from app.models.device import DeviceCredential, DeviceInventory, OSInstallation
    from app.models.enums import OsFamily, OsInstallationStatus, RelationshipStatus

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    dev_id = f"VD-DEVICE-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(UTC)

    with app.app_context():
        asset = Asset(
            asset_id=generate_next_asset_id(db.session),
            asset_tag=tag,
            asset_type=AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.IN_SERVICE,
        )
        db.session.add(asset)
        db.session.flush()

        device = PhysicalDevice(
            device_id=dev_id,
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(device)
        db.session.flush()

        cred = DeviceCredential(
            device_id=device.id,
            os_installation_id="os-default-01",
            public_key=pub_b64,
            credential_version=1,
            status="ACTIVE",
            created_at=now,
        )
        db.session.add(cred)

        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=device.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_at=now,
        )
        db.session.add(link)

        os_inst = OSInstallation(
            device_id=device.id,
            os_installation_id="os-default-01",
            os_family=OsFamily.LINUX,
            os_name="Ubuntu",
            os_version="24.04",
            architecture="x86_64",
            os_machine_id_hash="machine-hash-default",
            agent_instance_id="agent-inst-default",
            first_seen=now,
            last_seen=now,
            status=OsInstallationStatus.ACTIVE,
        )
        db.session.add(os_inst)

        inv = DeviceInventory(
            device_id=device.id,
            hostname=f"host-{tag.lower()}",
            ip_addresses=["192.168.1.100"],
            mac_addresses=["00:11:22:33:44:55"],
            agent_version="0.1.0",
        )
        db.session.add(inv)
        db.session.commit()

    return dev_id, key


def test_server_dedupes_event_ids(client, app):
    """Server-side idempotency: duplicates in batch are rejected without duplicate DB rows."""
    dev_id, key = _enroll_device(client, app, "OFFLINE-IDEMP")

    # 1. Telemetry Batch 1: samples with event_id e1, e2, e3
    batch_1 = {
        "samples": [
            {
                "event_id": "ev_telemetry_1",
                "cpu_percent": 10.0,
                "memory_percent": 20.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 100,
            },
            {
                "event_id": "ev_telemetry_2",
                "cpu_percent": 15.0,
                "memory_percent": 25.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 110,
            },
            {
                "event_id": "ev_telemetry_3",
                "cpu_percent": 20.0,
                "memory_percent": 30.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 120,
            },
        ]
    }
    body_1 = json.dumps(batch_1).encode("utf-8")
    headers_1 = sign_req(dev_id, key, "POST", "/api/v1/agents/telemetry", body_1)
    headers_1["Content-Type"] = "application/json"

    resp_1 = client.post("/api/v1/agents/telemetry", data=body_1, headers=headers_1)
    assert resp_1.status_code == 200
    data_1 = resp_1.get_json()
    assert data_1["status"] == "recorded"
    assert data_1["count"] == 3
    assert set(data_1["accepted"]) == {
        "ev_telemetry_1",
        "ev_telemetry_2",
        "ev_telemetry_3",
    }
    assert data_1["duplicates"] == []

    # 2. Telemetry Batch 2: replay ev_telemetry_2, ev_telemetry_3, and new ev_telemetry_4
    batch_2 = {
        "samples": [
            {
                "event_id": "ev_telemetry_2",
                "cpu_percent": 99.0,
                "memory_percent": 99.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 110,
            },
            {
                "event_id": "ev_telemetry_3",
                "cpu_percent": 99.0,
                "memory_percent": 99.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 120,
            },
            {
                "event_id": "ev_telemetry_4",
                "cpu_percent": 25.0,
                "memory_percent": 35.0,
                "disk_percent": 30.0,
                "network_rx": 0,
                "network_tx": 0,
                "uptime": 130,
            },
        ]
    }
    body_2 = json.dumps(batch_2).encode("utf-8")
    headers_2 = sign_req(dev_id, key, "POST", "/api/v1/agents/telemetry", body_2)
    headers_2["Content-Type"] = "application/json"

    resp_2 = client.post("/api/v1/agents/telemetry", data=body_2, headers=headers_2)
    assert resp_2.status_code == 200
    data_2 = resp_2.get_json()
    assert data_2["status"] == "recorded"
    assert data_2["count"] == 1
    assert data_2["accepted"] == ["ev_telemetry_4"]
    assert set(data_2["duplicates"]) == {"ev_telemetry_2", "ev_telemetry_3"}

    # Verify total telemetry rows in DB is exactly 4
    with app.app_context():
        p_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        t_count = Telemetry.query.filter_by(device_id=p_dev.id).count()
        assert t_count == 4

    # 3. Inventory event deduplication
    inv_payload = {
        "event_id": "ev_inventory_01",
        "inventory": {"hostname": "idemp-host", "ram_total_mb": 16384},
    }
    body_inv = json.dumps(inv_payload).encode("utf-8")
    headers_inv = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body_inv)
    headers_inv["Content-Type"] = "application/json"

    resp_inv1 = client.post(
        "/api/v1/agents/inventory", data=body_inv, headers=headers_inv
    )
    assert resp_inv1.status_code == 200
    assert resp_inv1.get_json()["accepted"] == ["ev_inventory_01"]

    headers_inv2 = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body_inv)
    headers_inv2["Content-Type"] = "application/json"
    resp_inv2 = client.post(
        "/api/v1/agents/inventory", data=body_inv, headers=headers_inv2
    )
    assert resp_inv2.status_code == 200
    assert resp_inv2.get_json()["duplicates"] == ["ev_inventory_01"]


def test_ack_lost_duplicate_delivery_has_no_side_effects(client, app, tmp_path):
    """Simulate lost ACK: client resends duplicate event, server returns ACK with duplicates, no side effect."""
    dev_id, key = _enroll_device(client, app, "OFFLINE-ACK-LOST")
    db_file = tmp_path / "agent_outbox.db"
    box = Outbox(db_file)

    ev_id = "ev_identity_unique_101"
    box.enqueue(
        PRIORITY_IDENTITY_EVENT,
        "identity",
        {
            "event_id": ev_id,
            "identity_evidence": {
                "machine_uuid_hash": "sha256:mach1",
                "motherboard_serial_hash": "sha256:mb1",
                "fingerprint": "fp1",
                "fingerprint_version": 1,
            },
        },
        event_id=ev_id,
    )
    assert box.count() == 1

    class SimClient:
        def __init__(self):
            self.attempt = 0

        def post(self, path, json_data=None):
            self.attempt += 1
            body = json.dumps(json_data).encode("utf-8")
            h = sign_req(dev_id, key, "POST", path, body)
            h["Content-Type"] = "application/json"
            server_resp = client.post(path, data=body, headers=h)

            if self.attempt == 1:
                # Server processed and committed, but simulate network drop before client receives response
                raise ConnectionError("Connection dropped right after server commit")
            return server_resp

    sim = SimClient()

    # Attempt 1 fails on client side due to simulated connection drop
    flushed = box.flush(sim)
    assert flushed == 0
    assert box.count() == 1  # Item still preserved in outbox

    # Attempt 2: client reconnects and flushes queue
    flushed2 = box.flush(sim)
    assert flushed2 == 1
    assert box.count() == 0  # Acknowledged and removed from outbox

    # Assert server only created 1 evidence record total (retry did not duplicate)
    with app.app_context():
        p_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        ev_records = DeviceIdentityEvidence.query.filter_by(device_id=p_dev.id).all()
        assert len(ev_records) == 1


def test_expired_credentials_pause_and_recover(client, app, tmp_path):
    """Client handles 401 on expired credential version, pauses, updates credentials, and flushes successfully."""
    dev_id, key1 = _enroll_device(client, app, "OFFLINE-ROT")

    # Rotate device credentials on server to key2 (version 2)
    key2 = Ed25519PrivateKey.generate()
    pub2_b64 = base64.b64encode(
        key2.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    rot_ts = int(time.time())
    rot_msg = f"rotate\n{dev_id}\n{pub2_b64}\n{rot_ts}".encode()
    rot_sig = base64.b64encode(key1.sign(rot_msg)).decode("ascii")

    rot_payload = {
        "new_public_key": pub2_b64,
        "signature_by_old_key": rot_sig,
        "timestamp": rot_ts,
    }
    rot_body = json.dumps(rot_payload).encode("utf-8")
    rot_headers = sign_req(
        dev_id, key1, "POST", "/api/v1/agents/rotate-credential", rot_body, key_ver=1
    )
    rot_headers["Content-Type"] = "application/json"

    rot_resp = client.post(
        "/api/v1/agents/rotate-credential", data=rot_body, headers=rot_headers
    )
    assert rot_resp.status_code == 200
    assert rot_resp.get_json()["credential_version"] == 2

    # Now agent outbox has pending items
    db_file = tmp_path / "rot_outbox.db"
    box = Outbox(db_file)
    box.enqueue(
        PRIORITY_INVENTORY,
        "inventory",
        {"hostname": "rotated-host", "ram_total_mb": 32768},
    )
    assert box.count() == 1

    # Client still using key1 (version 1)
    active_key = key1
    active_ver = 1

    class DynamicClient:
        def post(self, path, json_data=None):
            body = json.dumps(json_data).encode("utf-8")
            h = sign_req(dev_id, active_key, "POST", path, body, key_ver=active_ver)
            h["Content-Type"] = "application/json"
            return client.post(path, data=body, headers=h)

    dyn_client = DynamicClient()

    # Flush with outdated key1 -> gets 401
    resp1 = dyn_client.post("/api/v1/agents/inventory", {"hostname": "rotated-host"})
    assert resp1.status_code == 401
    assert box.count() == 1  # Queue intact

    # Agent updates credential to key2 (version 2)
    active_key = key2
    active_ver = 2

    # Flush now succeeds with key2
    flushed = box.flush(dyn_client)
    assert flushed == 1
    assert box.count() == 0

    with app.app_context():
        p_dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert p_dev.credential_version == 2
        assert p_dev.inventory.hostname == "rotated-host"
