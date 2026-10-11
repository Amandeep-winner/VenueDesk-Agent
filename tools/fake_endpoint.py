"""Simulates one or more endpoints for integration testing, fleet simulation, and full lifecycle validation."""
import argparse
import base64
import hashlib
import json
import time
import uuid

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_fake_evidence(index: int, identical_hardware: bool = False) -> dict:
    """Generate fake hardware identity evidence."""
    cpu = "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"
    gpus = ["NVIDIA GeForce RTX 3070"]
    disks = ["Samsung SSD 970 EVO 1TB"]

    machine_uuid = f"00000000-0000-0000-0000-{index:012x}"
    bios_serial = f"DELL-SER-{index:04d}" if not identical_hardware else "DELL-SER-BATCH-1"
    mobo_serial = f"MB-BASE-{index:04d}" if not identical_hardware else "MB-BASE-BATCH-1"

    salt = b"venuedesk-default-salt-32-chars-long!"
    def hmac_val(val: str) -> str:
        import hmac
        return hmac.new(salt, val.lower().encode(), hashlib.sha256).hexdigest()

    return {
        "machine_uuid_hash": hmac_val(machine_uuid),
        "bios_serial_hash": hmac_val(bios_serial),
        "motherboard_serial_hash": hmac_val(mobo_serial),
        "cpu_signature": cpu.lower(),
        "gpu_signature": gpus[0].lower(),
        "disk_identity_hash": hmac_val(disks[0]),
        "network_identity_hash": hmac_val(f"eth0:00:11:22:33:44:{index:02x}"),
        "tpm_identity": None,
        "fingerprint": hashlib.sha256(f"fake-fp-{index}".encode()).hexdigest(),
        "fingerprint_version": 1,
    }


def enroll_fake_endpoint(
    server_url: str,
    index: int,
    token: str | None = None,
    identical_hardware: bool = False,
) -> tuple[dict, Ed25519PrivateKey]:
    """Enroll a simulated fake endpoint against the VenueDesk server."""
    priv_key = Ed25519PrivateKey.generate()
    pub_raw = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")

    token_sha256 = hashlib.sha256(token.strip().encode("utf-8")).hexdigest() if token else ""
    ts = int(time.time())
    nonce = uuid.uuid4().hex
    msg = f"enroll\n{token_sha256}\n{ts}\n{nonce}".encode()
    sig = base64.b64encode(priv_key.sign(msg)).decode("ascii")

    evidence = generate_fake_evidence(index, identical_hardware=identical_hardware)
    inst_id = str(uuid.uuid4())
    payload = {
        "enrollment_token": token,
        "device_public_key": pub_b64,
        "proof_of_possession": sig,
        "timestamp": ts,
        "nonce": nonce,
        "identity_evidence": evidence,
        "inventory": {
            "hostname": f"fake-lab-pc-{index:02d}",
            "ip_addresses": [f"192.168.10.{100 + index}"],
            "mac_addresses": [f"00:11:22:33:44:{index:02x}"],
            "cpu_model": "Intel Core i7-10700",
            "cpu_cores": 8,
            "ram_total_mb": 16384,
            "gpus": ["NVIDIA GeForce RTX 3070"],
            "disks": ["Samsung SSD 970 EVO 1TB"],
            "os_summary": "Ubuntu 24.04 LTS",
            "agent_version": "0.1.0",
        },
        "os": {
            "family": "LINUX",
            "name": "Ubuntu",
            "version": "24.04",
            "architecture": "x86_64",
            "os_machine_id_hash": hashlib.sha256(f"os-mid-{index}".encode()).hexdigest(),
        },
        "agent_version": "0.1.0",
        "agent_instance_id": inst_id,
    }

    server_url = server_url.rstrip("/")
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{server_url}/api/v1/agents/enroll", json=payload)

    if resp.status_code != 200:
        raise RuntimeError(f"Fake endpoint {index} failed enrollment ({resp.status_code}): {resp.text}")

    res_json = resp.json()
    res_json["_agent_instance_id"] = inst_id
    return res_json, priv_key


def sign_req(dev_id: str, key: Ed25519PrivateKey, method: str, path: str, body: bytes, key_ver: int = 1) -> dict[str, str]:
    """Generate authenticated request headers."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    b_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{b_hash}".encode()
    sig = base64.b64encode(key.sign(canonical)).decode("ascii")
    return {
        "X-Device-ID": dev_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Version": str(key_ver),
        "X-Signature": sig,
    }


def send_fake_heartbeat(server_url: str, dev_id: str, key: Ed25519PrivateKey, inst_id: str) -> dict:
    """Send authenticated heartbeat."""
    body = json.dumps({"agent_instance_id": inst_id}).encode()
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    headers["Content-Type"] = "application/json"
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{server_url.rstrip('/')}/api/v1/agents/heartbeat", data=body, headers=headers)
    return resp.json() if resp.status_code == 200 else {}


def send_fake_telemetry(server_url: str, dev_id: str, key: Ed25519PrivateKey, count: int = 5) -> int:
    """Send synthetic telemetry samples."""
    samples = []
    now = int(time.time())
    for i in range(count):
        samples.append({
            "timestamp": now - (count - i) * 60,
            "cpu_percent": 15.0 + (i * 4.5) % 60,
            "memory_percent": 40.0 + (i * 2.5) % 40,
            "disk_percent": 50.0,
            "network_rx": 5000 + i * 100,
            "network_tx": 2500 + i * 50,
            "uptime": 3600 + i * 60,
        })
    body = json.dumps({"samples": samples}).encode()
    headers = sign_req(dev_id, key, "POST", "/api/v1/agents/telemetry", body)
    headers["Content-Type"] = "application/json"
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{server_url.rstrip('/')}/api/v1/agents/telemetry", data=body, headers=headers)
    return resp.status_code


def run_full_scenario(server_url: str) -> None:
    """Run full end-to-end lifecycle scenario against live server."""
    print("=" * 60)
    print(">>> Starting Full Lifecycle Scenario Simulation")
    print(f">>> Target Server: {server_url}")
    print("=" * 60)

    # 1. Unclaimed enrollment
    print("[1/6] Simulating unclaimed discovery endpoint...")
    try:
        res, key = enroll_fake_endpoint(server_url, index=99, token=None)
        dev_id = res["device_id"]
        inst_id = res["_agent_instance_id"]
        print(f"      Enrolled unclaimed device: {dev_id} (Status: {res.get('status')})")
    except Exception as exc:  # noqa: BLE001
        print(f"      Unclaimed mode note: {exc} (Enable ALLOW_UNCLAIMED_ENROLLMENT if testing unclaimed)")
        return

    # 2. Heartbeats
    print("[2/6] Sending initial heartbeats...")
    hb_res = send_fake_heartbeat(server_url, dev_id, key, inst_id)
    print(f"      Heartbeat response: {hb_res}")

    # 3. Telemetry batch
    print("[3/6] Sending telemetry metrics batch...")
    t_status = send_fake_telemetry(server_url, dev_id, key, count=10)
    print(f"      Telemetry submission status code: {t_status}")

    # 4. Inventory update with component changes
    print("[4/6] Updating inventory with simulated GPU upgrade...")
    upd_ev = generate_fake_evidence(99)
    upd_ev["gpu_signature"] = "nvidia rtx 4090"
    upd_inv = {
        "hostname": "fake-pc-upgraded",
        "ip_addresses": ["192.168.10.199"],
        "gpus": ["NVIDIA RTX 4090"],
    }
    inv_body = json.dumps({"inventory": upd_inv, "identity_evidence": upd_ev}).encode()
    inv_headers = sign_req(dev_id, key, "POST", "/api/v1/agents/inventory", inv_body)
    inv_headers["Content-Type"] = "application/json"
    with httpx.Client(timeout=10.0) as client:
        inv_resp = client.post(f"{server_url.rstrip('/')}/api/v1/agents/inventory", data=inv_body, headers=inv_headers)
    print(f"      Inventory reconciliation status: {inv_resp.status_code}")

    # 5. OS Reinstall Recovery simulation
    print("[5/6] Simulating OS reinstall recovery request...")
    new_key = Ed25519PrivateKey.generate()
    new_pub_b64 = base64.b64encode(
        new_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    r_ts = int(time.time())
    r_nonce = uuid.uuid4().hex
    r_proof = base64.b64encode(new_key.sign(f"recover\n{r_ts}\n{r_nonce}".encode())).decode("ascii")
    rec_body = {
        "device_public_key": new_pub_b64,
        "proof_of_possession": r_proof,
        "timestamp": r_ts,
        "nonce": r_nonce,
        "identity_evidence": upd_ev,
        "agent_instance_id": "inst-recovered-99",
        "os": {"family": "LINUX", "name": "Ubuntu", "version": "24.04.1", "architecture": "x86_64", "os_machine_id_hash": "mid-rec-99"},
    }
    with httpx.Client(timeout=10.0) as client:
        rec_resp = client.post(f"{server_url.rstrip('/')}/api/v1/agents/recover", json=rec_body)
    print(f"      Recovery endpoint response ({rec_resp.status_code}): {rec_resp.text}")

    print("=" * 60)
    print(">>> Scenario simulation completed successfully.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="VenueDesk Fake Endpoint Simulator")
    parser.add_argument("--server", default="http://127.0.0.1:5001", help="Control plane server URL")
    parser.add_argument("--count", type=int, default=1, help="Number of endpoints to simulate")
    parser.add_argument("--token", default=None, help="Pairing token (for single count)")
    parser.add_argument("--unclaimed", action="store_true", help="Enroll in unclaimed mode without token")
    parser.add_argument("--telemetry", action="store_true", help="Send telemetry samples for each endpoint")
    parser.add_argument("--scenario", choices=["all"], default=None, help="Run full scenario simulation")
    args = parser.parse_args()

    if args.scenario == "all":
        run_full_scenario(args.server)
        return

    for i in range(1, args.count + 1):
        tok = args.token if (args.count == 1 and not args.unclaimed) else None
        res, key = enroll_fake_endpoint(args.server, index=i, token=tok)
        dev_id = res["device_id"]
        inst_id = res["_agent_instance_id"]
        print(f"[{i}/{args.count}] Enrolled: {dev_id} -> Asset: {res.get('asset_id')}")

        if args.telemetry:
            send_fake_heartbeat(args.server, dev_id, key, inst_id)
            send_fake_telemetry(args.server, dev_id, key, count=10)
            print(f"      Sent heartbeats and 10 telemetry samples for {dev_id}")


if __name__ == "__main__":
    main()
