"""Agent-side identity and hardware evidence diffing and reconciliation."""

from typing import Any

from agent.identity.evidence import IdentityEvidence


def diff_evidence(
    old_evidence: IdentityEvidence | dict[str, Any] | None,
    new_evidence: IdentityEvidence | dict[str, Any],
) -> list[str]:
    """Detect which hardware identity evidence fields have changed locally."""
    if not old_evidence:
        return []

    old_dict = (
        old_evidence.to_dict() if isinstance(old_evidence, IdentityEvidence) else old_evidence
    )
    new_dict = (
        new_evidence.to_dict() if isinstance(new_evidence, IdentityEvidence) else new_evidence
    )

    changed = []
    comparable_fields = [
        "machine_uuid",
        "bios_serial",
        "motherboard_serial",
        "cpu",
        "gpus",
        "disks",
        "nics",
        "tpm_identity",
    ]

    for f in comparable_fields:
        v_old = old_dict.get(f)
        v_new = new_dict.get(f)
        if isinstance(v_old, list) and isinstance(v_new, list):
            if sorted(v_old) != sorted(v_new):
                changed.append(f)
        elif v_old != v_new:
            changed.append(f)

    return changed


def diff_inventory(
    old_inventory: dict[str, Any] | None,
    new_inventory: dict[str, Any],
) -> list[str]:
    """Detect which technical inventory fields have changed locally."""
    if not old_inventory:
        return []

    changed = []
    keys_to_compare = [
        "hostname",
        "ip_addresses",
        "mac_addresses",
        "cpu_model",
        "cpu_cores",
        "ram_total_mb",
        "gpus",
        "disks",
        "os_summary",
        "bios_version",
        "tpm_present",
    ]

    for k in keys_to_compare:
        o = old_inventory.get(k)
        n = new_inventory.get(k)
        if isinstance(o, list) and isinstance(n, list):
            if sorted(o) != sorted(n):
                changed.append(k)
        elif o != n:
            changed.append(k)

    return changed


def check_for_local_changes(
    last_sent_evidence: Any | None,
    current_evidence: Any,
    last_sent_inventory: dict[str, Any] | None,
    current_inventory: dict[str, Any],
) -> bool:
    """Detect local changes in evidence or inventory to trigger immediate reporting."""
    if last_sent_evidence:
        ev_diff = diff_evidence(last_sent_evidence, current_evidence)
        if ev_diff:
            return True
        old_dict = (
            last_sent_evidence.to_dict()
            if hasattr(last_sent_evidence, "to_dict")
            else (last_sent_evidence or {})
        )
        new_dict = (
            current_evidence.to_dict()
            if hasattr(current_evidence, "to_dict")
            else (current_evidence or {})
        )
        if (
            old_dict.get("fingerprint")
            and new_dict.get("fingerprint")
            and old_dict["fingerprint"] != new_dict["fingerprint"]
        ):
            return True

    if last_sent_inventory:
        inv_diff = diff_inventory(last_sent_inventory, current_inventory)
        if inv_diff:
            return True

    return False
