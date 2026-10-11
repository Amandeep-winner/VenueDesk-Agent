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
