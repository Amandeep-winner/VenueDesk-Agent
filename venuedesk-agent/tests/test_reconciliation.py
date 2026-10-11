"""Unit tests for agent-side identity and inventory diffing."""
from agent.identity.evidence import IdentityEvidence
from agent.identity.reconciliation import diff_evidence, diff_inventory


def test_diff_evidence_detects_hardware_changes():
    """Verify diff_evidence reports modified hardware fields."""
    ev1 = IdentityEvidence(
        machine_uuid="uuid-1",
        motherboard_serial="mb-1",
        bios_serial="bios-1",
        cpu="intel-i7",
        gpus=["rtx-3070"],
        disks=["disk-1"],
        nics=["eth0:00:11:22:33:44:55"],
        tpm_identity="tpm-1",
    )
    ev2 = IdentityEvidence(
        machine_uuid="uuid-1",
        motherboard_serial="mb-replaced",
        bios_serial="bios-1",
        cpu="intel-i7",
        gpus=["rtx-4090"],
        disks=["disk-1"],
        nics=["eth0:00:11:22:33:44:55"],
        tpm_identity="tpm-1",
    )

    diffs = diff_evidence(ev1, ev2)
    assert "motherboard_serial" in diffs
    assert "gpus" in diffs
    assert "machine_uuid" not in diffs


def test_diff_inventory_detects_inventory_changes():
    """Verify diff_inventory reports modified network, RAM, and disk fields."""
    inv1 = {
        "hostname": "host-1",
        "ip_addresses": ["10.0.0.1"],
        "ram_total_mb": 16384,
        "gpus": ["gpu1"],
    }
    inv2 = {
        "hostname": "host-1",
        "ip_addresses": ["10.0.0.2"],
        "ram_total_mb": 32768,
        "gpus": ["gpu1"],
    }

    diffs = diff_inventory(inv1, inv2)
    assert "ip_addresses" in diffs
    assert "ram_total_mb" in diffs
    assert "hostname" not in diffs
    assert "gpus" not in diffs
