"""Synthetic test fixtures and hardware definitions for comprehensive test suites."""
import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class SyntheticDevice:
    asset_tag: str
    asset_id: str
    hostname: str
    device_id: str
    key: Ed25519PrivateKey
    public_key_b64: str
    hardware: dict[str, Any]


def get_ai_lab_pc_07() -> SyntheticDevice:
    """Fixture representation of AI Lab workstation #07."""
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return SyntheticDevice(
        asset_tag="ASSET-AI-LAB-07",
        asset_id="VD-ASSET-000421",
        hostname="ai-lab-pc-07",
        device_id="VD-DEVICE-A1B2C307",
        key=key,
        public_key_b64=pub_b64,
        hardware={
            "machine_uuid": "00000000-0000-0000-0000-000000000421",
            "motherboard_serial": "MB-AI-0421",
            "bios_serial": "BIOS-AI-0421",
            "cpu_model": "Intel Core i9-14900K",
            "cpu_cores": 24,
            "ram_total_mb": 65536,
            "gpus": ["NVIDIA RTX 4090 24GB"],
            "disks": ["Samsung SSD 990 PRO 2TB"],
            "mac_addresses": ["00:11:22:33:44:21"],
        },
    )


def get_cse_lab_pc_12() -> SyntheticDevice:
    """Fixture representation of CSE Lab computer #12."""
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return SyntheticDevice(
        asset_tag="ASSET-CSE-LAB-12",
        asset_id="VD-ASSET-000422",
        hostname="cse-lab-pc-12",
        device_id="VD-DEVICE-C5E6D712",
        key=key,
        public_key_b64=pub_b64,
        hardware={
            "machine_uuid": "00000000-0000-0000-0000-000000000422",
            "motherboard_serial": "MB-CSE-0422",
            "bios_serial": "BIOS-CSE-0422",
            "cpu_model": "AMD Ryzen 9 7950X",
            "cpu_cores": 16,
            "ram_total_mb": 32768,
            "gpus": ["NVIDIA RTX 4080 16GB"],
            "disks": ["WD_BLACK SN850X 1TB"],
            "mac_addresses": ["00:11:22:33:44:22"],
        },
    )


def get_identical_hardware_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return two devices with identical specs/models but differing serial numbers and UUIDs."""
    dev_a = {
        "cpu_model": "Intel Core i7-13700",
        "cpu_cores": 16,
        "ram_total_mb": 32768,
        "motherboard_model": "ASUS PRIME B760-PLUS",
        "bios_version": "1604",
        "gpu_model": "NVIDIA GeForce RTX 4070",
        "disk_model": "Crucial P5 Plus 1TB",
        "machine_uuid": "11111111-1111-1111-1111-111111111111",
        "motherboard_serial": "ASUS-MB-SER-111",
        "bios_serial": "ASUS-BIOS-SER-111",
    }
    dev_b = {
        "cpu_model": "Intel Core i7-13700",
        "cpu_cores": 16,
        "ram_total_mb": 32768,
        "motherboard_model": "ASUS PRIME B760-PLUS",
        "bios_version": "1604",
        "gpu_model": "NVIDIA GeForce RTX 4070",
        "disk_model": "Crucial P5 Plus 1TB",
        "machine_uuid": "22222222-2222-2222-2222-222222222222",
        "motherboard_serial": "ASUS-MB-SER-222",
        "bios_serial": "ASUS-BIOS-SER-222",
    }
    return dev_a, dev_b


def get_device_missing_serials() -> dict[str, Any]:
    """Return a hardware spec observation with OEM default strings and missing serials."""
    return {
        "cpu_model": "Generic OEM CPU",
        "cpu_cores": 8,
        "ram_total_mb": 16384,
        "motherboard_model": "OEM Base Board",
        "motherboard_serial": "To Be Filled By O.E.M.",
        "bios_serial": "Default string",
        "machine_uuid": "00000000-0000-0000-0000-000000000000",
        "chassis_serial": "None",
    }
