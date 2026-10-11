"""Integration and unit tests for inventory ingestion, telemetry batching, retention pruning, and admin query API."""
import base64
import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.extensions import db
from app.models import (
    DeviceInventory,
    DeviceStatus,
    OSInstallation,
    PhysicalDevice,
    Telemetry,
    User,
    UserRole,
    generate_device_id,
)
from app.services.telemetry_service import purge_telemetry


def create_test_device(app) -> tuple[str, Ed25519PrivateKey]:
    """Helper creating a test physical device."""
    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    dev_id = generate_device_id()
    now = datetime.now(UTC)

    with app.app_context():
        device = PhysicalDevice(
            device_id=dev_id,
            device_public_key=pub_b64,
            credential_version=1,
            status=DeviceStatus.ACTIVE,
            first_seen=now,
            last_seen=now,
        )
        db.session.add(device)
        db.session.commit()

    return dev_id, key


def sign_req(dev_id: str, key: Ed25519PrivateKey, method: str, path: str, body: bytes) -> dict[str, str]:
    """Helper generating auth headers for test client."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    b_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{b_hash}".encode()
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": "1",
        "X-Signature": sig,
    }


def test_post_inventory_updates_inventory_and_os(client, app):
    """Test POST /api/v1/agents/inventory upserts DeviceInventory and OSInstallation."""
    dev_id, key = create_test_device(app)

    payload = {
        "inventory": {
            "hostname": "ai-lab-ws01",
            "ip_addresses": ["192.168.1.101"],
            "mac_addresses": ["00:1a:2b:3c:4d:5e"],
            "cpu_model": "Intel Core i7-13700K",
            "cpu_cores": 16,
            "ram_total_mb": 32768,
            "gpus": ["NVIDIA RTX 4080"],
            "disks": ["Samsung 980 PRO 1TB"],
            "os_summary": "Ubuntu 24.04 (x86_64)",
            "bios_version": "v1.40",
            "tpm_present": True,
            "agent_version": "0.1.0",
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": "mid-hash-12345",
        },
        "agent_instance_id": "inst-abc-123",
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", body_bytes)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/inventory", data=body_bytes, headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "inventory_updated"

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        assert dev is not None
        inv = DeviceInventory.query.filter_by(device_id=dev.id).first()
        assert inv is not None
        assert inv.hostname == "ai-lab-ws01"
        assert inv.cpu_cores == 16
        assert inv.ram_total_mb == 32768
        assert inv.gpus == ["NVIDIA RTX 4080"]
        assert inv.tpm_present is True

        os_inst = OSInstallation.query.filter_by(device_id=dev.id).first()
        assert os_inst is not None
        assert os_inst.os_name == "Ubuntu"
        assert os_inst.os_machine_id_hash == "mid-hash-12345"


def test_post_telemetry_batch_and_query_api(client, app):
    """Test batch telemetry ingestion and admin query API."""
    dev_id, key = create_test_device(app)

    # 1. Post batch of telemetry samples
    now_iso = datetime.now(UTC).isoformat()
    samples = [
        {
            "timestamp": now_iso,
            "cpu_percent": 15.5,
            "memory_percent": 42.0,
            "disk_percent": 68.2,
            "network_rx": 10240,
            "network_tx": 20480,
            "uptime": 3600.0,
            "load_average": 0.45,
            "gpu_percent": 12.0,
            "gpu_mem_percent": 25.0,
            "temperature_c": 55.0,
        },
        {
            "timestamp": now_iso,
            "cpu_percent": 22.1,
            "memory_percent": 43.5,
            "disk_percent": 68.2,
            "network_rx": 15000,
            "network_tx": 25000,
            "uptime": 3660.0,
            "load_average": 0.52,
            "gpu_percent": 18.0,
            "gpu_mem_percent": 27.0,
            "temperature_c": 57.0,
        },
    ]

    payload = {"samples": samples}
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/telemetry", body_bytes)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/telemetry", data=body_bytes, headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 2

    # 2. Query telemetry as admin
    with app.app_context():
        admin = User.query.filter_by(username="telem_admin").first()
        if not admin:
            admin = User(username="telem_admin", role=UserRole.INFRA_ADMIN)
            admin.set_password("adminpass")
            db.session.add(admin)
            db.session.commit()

    admin_headers = {
        "Authorization": "Basic " + base64.b64encode(b"telem_admin:adminpass").decode("ascii")
    }
    query_resp = client.get(f"/api/v1/admin/devices/{dev_id}/telemetry", headers=admin_headers)
    assert query_resp.status_code == 200
    data = query_resp.get_json()
    assert data["count"] == 2
    assert len(data["telemetry"]) == 2
    assert data["telemetry"][0]["cpu_percent"] in (15.5, 22.1)


def test_post_telemetry_batch_limit_exceeded_returns_413(client, app):
    """Test that submitting more than 500 samples in a batch returns 413 Payload Too Large."""
    dev_id, key = create_test_device(app)

    samples = [
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "cpu_percent": 5.0,
            "memory_percent": 10.0,
            "disk_percent": 20.0,
            "network_rx": 100,
            "network_tx": 200,
            "uptime": 100.0,
        }
        for _ in range(501)
    ]

    payload = {"samples": samples}
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/telemetry", body_bytes)
    headers["Content-Type"] = "application/json"

    resp = client.post("/api/v1/agents/telemetry", data=body_bytes, headers=headers)
    assert resp.status_code == 413
    assert resp.get_json()["error"] == "payload_too_large"


def test_telemetry_retention_purge_and_cli(client, app):
    """Test purging telemetry older than threshold days and CLI command."""
    dev_id, _key = create_test_device(app)

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        now = datetime.now(UTC)
        old_time = now - timedelta(days=45)
        recent_time = now - timedelta(days=5)

        # Old sample
        db.session.add(
            Telemetry(
                device_id=dev.id,
                timestamp=old_time,
                cpu_percent=10.0,
                memory_percent=20.0,
                disk_percent=30.0,
                network_rx=0,
                network_tx=0,
                uptime=100.0,
            )
        )
        # Recent sample
        db.session.add(
            Telemetry(
                device_id=dev.id,
                timestamp=recent_time,
                cpu_percent=15.0,
                memory_percent=25.0,
                disk_percent=35.0,
                network_rx=0,
                network_tx=0,
                uptime=200.0,
            )
        )
        db.session.commit()

        # Purge older than 30 days
        deleted = purge_telemetry(older_than_days=30)
        assert deleted == 1

        remaining = Telemetry.query.filter_by(device_id=dev.id).all()
        assert len(remaining) == 1
        assert remaining[0].cpu_percent == 15.0

    # Test CLI runner for purge-telemetry
    runner = app.test_cli_runner()
    result = runner.invoke(args=["purge-telemetry", "--older-than-days", "30"])
    assert result.exit_code == 0
    assert "Purged" in result.output
