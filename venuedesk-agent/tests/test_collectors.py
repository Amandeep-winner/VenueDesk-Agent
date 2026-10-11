"""Unit tests for collector graceful degradation."""
import subprocess
from unittest.mock import patch

from agent.collectors import (
    collect_bios_serial,
    collect_disks,
    collect_gpus,
    collect_identity_evidence,
    collect_machine_uuid,
    collect_motherboard_serial,
    collect_tpm_identity,
)
from agent.collectors.system import collect_os_info


def test_collectors_degrade_gracefully_on_subprocess_error():
    """Verify all collectors return None or empty list instead of crashing when commands fail."""
    with patch("subprocess.run", side_effect=subprocess.SubprocessError("Command failed")):
        assert collect_machine_uuid() is None
        assert collect_bios_serial() is None
        assert collect_motherboard_serial() is None
        assert collect_tpm_identity() is None
        assert collect_disks() == []
        assert collect_gpus() == []


def test_collectors_degrade_gracefully_on_file_not_found():
    """Verify collectors handle FileNotFoundError when commands don't exist."""
    with patch("subprocess.run", side_effect=FileNotFoundError("powershell not found")):
        assert collect_machine_uuid() is None
        assert collect_bios_serial() is None
        assert collect_motherboard_serial() is None
        assert collect_disks() == []
        assert collect_gpus() == []


def test_collect_os_info_structure():
    info = collect_os_info()
    assert "family" in info
    assert "name" in info
    assert "version" in info
    assert "architecture" in info
    assert "os_machine_id_hash" in info
    assert len(info["os_machine_id_hash"]) == 64


def test_collect_identity_evidence_returns_evidence_object():
    ev = collect_identity_evidence()
    assert hasattr(ev, "machine_uuid")
    assert hasattr(ev, "bios_serial")
    assert hasattr(ev, "motherboard_serial")
    assert hasattr(ev, "cpu")
    assert isinstance(ev.gpus, list)
    assert isinstance(ev.disks, list)
    assert isinstance(ev.nics, list)
    # Ensure fingerprint computation does not crash
    fp = ev.compute_fingerprint()
    assert len(fp) == 64


def test_collect_processes_and_services():
    from agent.collectors.processes import collect_processes
    from agent.collectors.services import collect_services

    procs = collect_processes(limit=5)
    assert isinstance(procs, list)
    if procs:
        p0 = procs[0]
        assert "pid" in p0
        assert "name" in p0

    svcs = collect_services()
    assert isinstance(svcs, list)


def test_collect_full_inventory_and_telemetry():
    from agent.collectors import collect_full_inventory, collect_telemetry_sample

    inv = collect_full_inventory()
    assert isinstance(inv, dict)
    assert "hostname" in inv
    assert "ip_addresses" in inv
    assert "mac_addresses" in inv
    assert "os_summary" in inv
    assert "agent_version" in inv
    assert inv["agent_version"] == "0.1.0"

    telem = collect_telemetry_sample()
    assert isinstance(telem, dict)
    assert "cpu_percent" in telem
    assert "memory_percent" in telem
    assert "disk_percent" in telem
    assert "uptime" in telem
    assert "timestamp" in telem

