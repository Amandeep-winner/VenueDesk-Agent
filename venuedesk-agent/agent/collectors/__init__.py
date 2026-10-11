"""Hardware and system collectors with graceful degradation."""
from agent.collectors.gpu import collect_gpus
from agent.collectors.hardware import (
    collect_bios_serial,
    collect_cpu_model,
    collect_motherboard_serial,
    collect_tpm_identity,
)
from agent.collectors.network import collect_nics
from agent.collectors.storage import collect_disks
from agent.collectors.system import collect_machine_uuid
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
