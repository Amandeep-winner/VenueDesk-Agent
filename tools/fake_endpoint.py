"""Simulates one or more endpoints for integration testing and fleet simulation."""
import argparse
import base64
import hashlib
import time
import uuid

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_fake_evidence(index: int, identical_hardware: bool = False) -> dict:
    """Generate fake hardware identity evidence."""
    # Near identical hardware for fleet testing
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
) -> dict:
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
        "agent_instance_id": str(uuid.uuid4()),
    }

    server_url = server_url.rstrip("/")
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{server_url}/api/v1/agents/enroll", json=payload)

    if resp.status_code != 200:
        raise RuntimeError(f"Fake endpoint {index} failed enrollment ({resp.status_code}): {resp.text}")

    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="VenueDesk Fake Endpoint Simulator")
    parser.add_argument("--server", default="http://127.0.0.1:5001", help="Control plane server URL")
    parser.add_argument("--count", type=int, default=1, help="Number of endpoints to simulate")
    parser.add_argument("--token", default=None, help="Pairing token (for single count)")
    parser.add_argument("--unclaimed", action="store_true", help="Enroll in unclaimed mode without token")
    args = parser.parse_args()

    for i in range(1, args.count + 1):
        tok = args.token if (args.count == 1 and not args.unclaimed) else None
        res = enroll_fake_endpoint(args.server, index=i, token=tok)
        print(f"[{i}/{args.count}] Enrolled: {res['device_id']} -> Asset: {res.get('asset_id')}")


if __name__ == "__main__":
    main()
