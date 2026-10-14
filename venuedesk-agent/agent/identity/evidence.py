"""Hardware identity evidence data structures and anchor extraction."""

from dataclasses import dataclass, field
from typing import Any

from agent.identity.fingerprint import (
    FINGERPRINT_VERSION,
    compute_fingerprint,
    field_hash,
    filter_nics,
    norm,
    norm_list,
)


@dataclass
class IdentityEvidence:
    """Collected raw hardware identifiers and anchors."""

    machine_uuid: str | None = None
    bios_serial: str | None = None
    motherboard_serial: str | None = None
    cpu: str | None = None
    gpus: list[str] = field(default_factory=list)
    disks: list[str] = field(default_factory=list)
    nics: list[str] = field(default_factory=list)
    tpm_identity: str | None = None

    def strong_anchors(self) -> set[str]:
        """Return the set of present strong anchors (machine_uuid, motherboard_serial, bios_serial, tpm_identity)."""
        anchors = set()
        if norm(self.machine_uuid):
            anchors.add("machine_uuid")
        if norm(self.motherboard_serial):
            anchors.add("motherboard_serial")
        if norm(self.bios_serial):
            anchors.add("bios_serial")
        if norm(self.tpm_identity):
            anchors.add("tpm_identity")
        return anchors

    def to_dict(self) -> dict[str, Any]:
        """Return raw evidence dictionary."""
        return {
            "machine_uuid": self.machine_uuid,
            "bios_serial": self.bios_serial,
            "motherboard_serial": self.motherboard_serial,
            "cpu": self.cpu,
            "gpus": self.gpus,
            "disks": self.disks,
            "nics": self.nics,
            "tpm_identity": self.tpm_identity,
        }

    def compute_fingerprint(self, version: int = FINGERPRINT_VERSION) -> str:
        """Compute the deterministic SHA-256 fingerprint for this evidence."""
        return compute_fingerprint(self.to_dict(), version=version)

    def to_evidence_payload(
        self, salt: bytes, version: int = FINGERPRINT_VERSION
    ) -> dict[str, Any]:
        """Format evidence into salted HMAC hashes and signatures for transmission to control plane."""
        normalized_disks = norm_list(self.disks)
        disk_sig = ",".join(normalized_disks) if normalized_disks else None

        normalized_nics = norm_list(filter_nics(self.nics))
        net_sig = ",".join(normalized_nics) if normalized_nics else None

        normalized_gpus = norm_list(self.gpus)
        gpu_sig = ",".join(normalized_gpus) if normalized_gpus else None

        return {
            "machine_uuid_hash": field_hash(salt, self.machine_uuid),
            "bios_serial_hash": field_hash(salt, self.bios_serial),
            "motherboard_serial_hash": field_hash(salt, self.motherboard_serial),
            "cpu_signature": norm(self.cpu),
            "gpu_signature": gpu_sig,
            "disk_identity_hash": field_hash(salt, disk_sig),
            "network_identity_hash": field_hash(salt, net_sig),
            "tpm_identity": field_hash(salt, self.tpm_identity),
            "fingerprint": self.compute_fingerprint(version=version),
            "fingerprint_version": version,
        }
