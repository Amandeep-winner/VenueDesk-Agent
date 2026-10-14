"""Hardware and system collectors with graceful degradation."""

from typing import Any

from agent.collectors.gpu import collect_gpus
from agent.collectors.hardware import (
    collect_bios_serial,
    collect_cpu_model,
    collect_motherboard_serial,
    collect_tpm_identity,
)
from agent.collectors.network import collect_nics
from agent.collectors.processes import collect_processes
from agent.collectors.services import collect_services
from agent.collectors.storage import collect_disks
from agent.collectors.system import (
    collect_bios_version,
    collect_cpu_cores,
    collect_hostname,
    collect_ip_addresses,
    collect_mac_addresses,
    collect_machine_uuid,
    collect_os_info,
    collect_os_machine_id,
    collect_os_summary,
    collect_ram_total_mb,
    collect_tpm_present,
)
from agent.collectors.telemetry import collect_telemetry_sample
from agent.identity.evidence import IdentityEvidence


def collect_identity_evidence() -> IdentityEvidence:
    """Collect identity evidence across all hardware collectors with graceful degradation."""
    return IdentityEvidence(
        machine_uuid=collect_machine_uuid(),
        bios_serial=collect_bios_serial(),
        motherboard_serial=collect_motherboard_serial(),
        cpu=collect_cpu_model(),
        gpus=collect_gpus(),
        disks=collect_disks(),
        nics=collect_nics(),
        tpm_identity=collect_tpm_identity(),
    )


def collect_full_inventory(agent_version: str = "0.1.0") -> dict[str, Any]:
    """Collect full observed technical inventory snapshot."""
    return {
        "hostname": collect_hostname(),
        "ip_addresses": collect_ip_addresses(),
        "mac_addresses": collect_mac_addresses(),
        "cpu_model": collect_cpu_model(),
        "cpu_cores": collect_cpu_cores(),
        "ram_total_mb": collect_ram_total_mb(),
        "gpus": collect_gpus(),
        "disks": collect_disks(),
        "os_summary": collect_os_summary(),
        "bios_version": collect_bios_version(),
        "tpm_present": collect_tpm_present(),
        "agent_version": agent_version,
    }


__all__ = [
    "IdentityEvidence",
    "collect_bios_serial",
    "collect_bios_version",
    "collect_cpu_cores",
    "collect_cpu_model",
    "collect_disks",
    "collect_full_inventory",
    "collect_gpus",
    "collect_hostname",
    "collect_identity_evidence",
    "collect_ip_addresses",
    "collect_mac_addresses",
    "collect_machine_uuid",
    "collect_motherboard_serial",
    "collect_nics",
    "collect_os_info",
    "collect_os_machine_id",
    "collect_os_summary",
    "collect_processes",
    "collect_ram_total_mb",
    "collect_services",
    "collect_telemetry_sample",
    "collect_tpm_identity",
    "collect_tpm_present",
]
