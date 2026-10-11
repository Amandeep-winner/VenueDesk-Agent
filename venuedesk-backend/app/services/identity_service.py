"""Identity reconciliation, diffing, similarity scoring, and decision engine."""
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceStatus,
    EventSeverity,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
)

logger = logging.getLogger(__name__)


class IdentityDecision(str, Enum):
    """Outcomes from identity decision engine."""
    SAME_DEVICE = "SAME_DEVICE"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    PENDING_REVERIFICATION = "PENDING_REVERIFICATION"
    AMBIGUOUS = "AMBIGUOUS"
    MANUAL_VERIFICATION = "MANUAL_VERIFICATION"


@dataclass
class Observation:
    """Incoming endpoint observation evaluated by decision engine."""
    device_id: str | None = None
    device_public_key: str | None = None
    signature_valid: bool = False
    valid_signature_for_active_device: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, Any] | None = None
    os: dict[str, Any] | None = None
    agent_instance_id: str | None = None


DEFAULT_SCORING_WEIGHTS = {
    "machine_uuid": 40.0,
    "motherboard": 25.0,
    "bios": 15.0,
    "cpu": 10.0,
    "disk": 5.0,
    "nic": 5.0,
}


def _norm(val: Any) -> str | None:
    if val is None:
        return None
    s = " ".join(str(val).strip().lower().split())
    if s in ("", "none", "unknown", "null"):
        return None
    return s


def calculate_similarity_score(
    ev_a: dict[str, Any],
    ev_b: dict[str, Any],
    weights: dict[str, float] | None = None,
) -> float:
    """Calculate normalized similarity score (0.0 to 100.0) between two evidence dictionaries."""
    w = weights or DEFAULT_SCORING_WEIGHTS

    field_map = {
        "machine_uuid": ("machine_uuid_hash", "machine_uuid"),
        "motherboard": ("motherboard_serial_hash", "motherboard_serial"),
        "bios": ("bios_serial_hash", "bios_serial"),
        "cpu": ("cpu_signature", "cpu"),
        "disk": ("disk_identity_hash", "disks"),
        "nic": ("network_identity_hash", "nics"),
    }

    total_possible_weight = 0.0
    accumulated_score = 0.0

    for weight_key, attr_keys in field_map.items():
        weight = w.get(weight_key, 0.0)

        # Extract values using either hash key or raw key
        val_a = None
        for k in attr_keys:
            if ev_a.get(k) is not None:
                val_a = ev_a[k]
                break

        val_b = None
        for k in attr_keys:
            if ev_b.get(k) is not None:
                val_b = ev_b[k]
                break

        norm_a = _norm(val_a)
        norm_b = _norm(val_b)

        # Missing in both -> exclude from denominator
        if norm_a is None and norm_b is None:
            continue

        total_possible_weight += weight

        # Both present and equal -> full field weight
        if norm_a is not None and norm_b is not None and norm_a == norm_b:
            accumulated_score += weight

    if total_possible_weight <= 0.0:
        return 0.0

    return round((accumulated_score / total_possible_weight) * 100.0, 2)


def evidence_is_strong(candidate: PhysicalDevice, obs: Observation) -> bool:
    """Return True if candidate and observation share >= 2 matching strong anchors."""
    ref_ev = (
        DeviceIdentityEvidence.query.filter_by(device_id=candidate.id, trusted=True)
        .order_by(DeviceIdentityEvidence.captured_at.desc())
        .first()
    )
    if not ref_ev:
        ref_ev = (
            DeviceIdentityEvidence.query.filter_by(device_id=candidate.id)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .first()
        )
    if not ref_ev:
        return False

    strong_matches = 0
    obs_ev = obs.evidence

    anchors = [
        ("machine_uuid_hash", ["machine_uuid_hash", "machine_uuid"]),
        ("motherboard_serial_hash", ["motherboard_serial_hash", "motherboard_serial"]),
        ("bios_serial_hash", ["bios_serial_hash", "bios_serial"]),
        ("tpm_identity", ["tpm_identity"]),
    ]

    for ref_attr, obs_keys in anchors:
        ref_val = _norm(getattr(ref_ev, ref_attr, None))
        obs_val = None
        for k in obs_keys:
            if obs_ev.get(k) is not None:
                obs_val = _norm(obs_ev[k])
                break

        if ref_val is not None and obs_val is not None and ref_val == obs_val:
            strong_matches += 1

    return strong_matches >= 2


def find_candidates_by_evidence(obs: Observation) -> list[tuple[PhysicalDevice, float]]:
    """Find and rank existing physical devices by hardware similarity score."""
    obs_ev = obs.evidence
    if not obs_ev:
        return []

    # Get all candidate devices
    devices = PhysicalDevice.query.filter(
        PhysicalDevice.status.notin_([DeviceStatus.REVOKED, DeviceStatus.RETIRED])
    ).all()

    candidates: list[tuple[PhysicalDevice, float]] = []

    for dev in devices:
        ref_ev = (
            DeviceIdentityEvidence.query.filter_by(device_id=dev.id, trusted=True)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .first()
        )
        if not ref_ev:
            ref_ev = (
                DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
                .order_by(DeviceIdentityEvidence.captured_at.desc())
                .first()
            )
        if not ref_ev:
            continue

        ref_dict = {
            "machine_uuid_hash": ref_ev.machine_uuid_hash,
            "motherboard_serial_hash": ref_ev.motherboard_serial_hash,
            "bios_serial_hash": ref_ev.bios_serial_hash,
            "cpu_signature": ref_ev.cpu_signature,
            "disk_identity_hash": ref_ev.disk_identity_hash,
            "network_identity_hash": ref_ev.network_identity_hash,
            "tpm_identity": ref_ev.tpm_identity,
        }

        score = calculate_similarity_score(ref_dict, obs_ev)
        if score > 0.0:
            candidates.append((dev, score))

    # Rank by similarity score descending
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates


def determine_device_identity(obs: Observation) -> tuple[IdentityDecision, list[PhysicalDevice], float]:
    """Identity decision engine per specification §4.7.
    
    Security Invariant: A high similarity score is advisory only and NEVER links an asset.
    """
    if obs.valid_signature_for_active_device:
        dev = PhysicalDevice.query.filter_by(device_id=obs.device_id).first() if obs.device_id else None
        return IdentityDecision.SAME_DEVICE, [dev] if dev else [], 100.0

    candidates_with_scores = find_candidates_by_evidence(obs)
    if not candidates_with_scores:
        return IdentityDecision.UNKNOWN_DEVICE, [], 0.0

    candidates = [c[0] for c in candidates_with_scores]
    best_score = candidates_with_scores[0][1]

    if len(candidates) > 1:
        # Check if top candidate shares >= 2 strong anchors with others or equal score
        top_score = candidates_with_scores[0][1]
        second_score = candidates_with_scores[1][1]
        if abs(top_score - second_score) < 5.0:
            return IdentityDecision.AMBIGUOUS, candidates, best_score

    if evidence_is_strong(candidates[0], obs):
        return IdentityDecision.PENDING_REVERIFICATION, candidates, best_score

    return IdentityDecision.MANUAL_VERIFICATION, candidates, best_score


def reconcile_device_evidence(device: PhysicalDevice, new_evidence: dict[str, Any]) -> list[DeviceEvent]:
    """Diff new evidence against last trusted evidence snapshot and emit audited events."""
    # Reference snapshot: last trusted=True snapshot, fallback to latest prior snapshot
    ref_ev = (
        DeviceIdentityEvidence.query.filter(
            DeviceIdentityEvidence.device_id == device.id,
            DeviceIdentityEvidence.trusted.is_(True),
        )
        .order_by(DeviceIdentityEvidence.captured_at.desc())
        .first()
    )
    if not ref_ev:
        # Fallback to second latest snapshot if present
        snapshots = (
            DeviceIdentityEvidence.query.filter_by(device_id=device.id)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .limit(2)
            .all()
        )
        if len(snapshots) >= 2:
            ref_ev = snapshots[1]
        else:
            return []

    events: list[DeviceEvent] = []
    now = datetime.now(UTC)

    # 1. Motherboard serial changed -> MOTHERBOARD_CHANGED (HIGH)
    ref_mb = _norm(ref_ev.motherboard_serial_hash)
    new_mb = _norm(new_evidence.get("motherboard_serial_hash") or new_evidence.get("motherboard_serial"))
    if ref_mb is not None and new_mb is not None and ref_mb != new_mb:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.MOTHERBOARD_CHANGED,
            severity=EventSeverity.HIGH,
            payload={"old_motherboard_serial_hash": ref_mb, "new_motherboard_serial_hash": new_mb},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 2. TPM identity changed -> TPM_CHANGED (HIGH)
    ref_tpm = _norm(ref_ev.tpm_identity)
    new_tpm = _norm(new_evidence.get("tpm_identity"))
    if ref_tpm is not None and new_tpm is not None and ref_tpm != new_tpm:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.TPM_CHANGED,
            severity=EventSeverity.HIGH,
            payload={"old_tpm": ref_tpm, "new_tpm": new_tpm},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 3. Check for >= 2 strong anchor changes -> IDENTITY_CHANGE_DETECTED (HIGH)
    strong_anchors_changed = 0
    anchors = [
        ("machine_uuid_hash", ["machine_uuid_hash", "machine_uuid"]),
        ("motherboard_serial_hash", ["motherboard_serial_hash", "motherboard_serial"]),
        ("bios_serial_hash", ["bios_serial_hash", "bios_serial"]),
        ("tpm_identity", ["tpm_identity"]),
    ]

    for attr, keys in anchors:
        o_val = _norm(getattr(ref_ev, attr, None))
        n_val = None
        for k in keys:
            if new_evidence.get(k) is not None:
                n_val = _norm(new_evidence[k])
                break
        if o_val is not None and n_val is not None and o_val != n_val:
            strong_anchors_changed += 1

    if strong_anchors_changed >= 2:
        device.status = DeviceStatus.PENDING_REVERIFICATION
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.IDENTITY_CHANGE_DETECTED,
            severity=EventSeverity.HIGH,
            payload={
                "message": f"{strong_anchors_changed} strong hardware anchors changed",
                "changed_count": strong_anchors_changed,
            },
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    if events:
        db.session.commit()

    return events


def reconcile_device_inventory(
    device: PhysicalDevice,
    new_inventory: dict[str, Any],
    new_os: dict[str, Any] | None = None,
) -> list[DeviceEvent]:
    """Diff new inventory against prior inventory snapshot and emit audited events."""
    inv = DeviceInventory.query.filter_by(device_id=device.id).first()
    if not inv:
        return []

    events: list[DeviceEvent] = []
    now = datetime.now(UTC)

    # 1. IP changed -> IP_CHANGED (LOW)
    new_ips = sorted(new_inventory.get("ip_addresses") or [])
    old_ips = sorted(inv.ip_addresses or [])
    if old_ips and new_ips and old_ips != new_ips:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.IP_CHANGED,
            severity=EventSeverity.LOW,
            payload={"old_ips": old_ips, "new_ips": new_ips},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 2. Hostname changed -> HOSTNAME_CHANGED (LOW)
    new_host = new_inventory.get("hostname")
    if inv.hostname and new_host and inv.hostname != new_host and inv.hostname != "unknown":
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.HOSTNAME_CHANGED,
            severity=EventSeverity.LOW,
            payload={"old_hostname": inv.hostname, "new_hostname": new_host},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 3. RAM total changed -> RAM_CHANGED (LOW)
    new_ram = new_inventory.get("ram_total_mb")
    if inv.ram_total_mb and new_ram and inv.ram_total_mb != new_ram:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.RAM_CHANGED,
            severity=EventSeverity.LOW,
            payload={"old_ram_mb": inv.ram_total_mb, "new_ram_mb": new_ram},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 4. GPU changed -> GPU_CHANGED (LOW)
    new_gpus = sorted(new_inventory.get("gpus") or [])
    old_gpus = sorted(inv.gpus or [])
    if old_gpus and new_gpus and old_gpus != new_gpus:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.GPU_CHANGED,
            severity=EventSeverity.LOW,
            payload={"old_gpus": old_gpus, "new_gpus": new_gpus},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 5. Disk changed -> DISK_CHANGED (MEDIUM)
    new_disks = sorted(new_inventory.get("disks") or [])
    old_disks = sorted(inv.disks or [])
    if old_disks and new_disks and old_disks != new_disks:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.DISK_CHANGED,
            severity=EventSeverity.MEDIUM,
            payload={"old_disks": old_disks, "new_disks": new_disks},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 6. NIC changed -> NIC_CHANGED (MEDIUM)
    new_macs = sorted(new_inventory.get("mac_addresses") or [])
    old_macs = sorted(inv.mac_addresses or [])
    if old_macs and new_macs and old_macs != new_macs:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=DeviceEventType.NIC_CHANGED,
            severity=EventSeverity.MEDIUM,
            payload={"old_macs": old_macs, "new_macs": new_macs},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

    # 7. OS changed -> OS_CHANGED (MEDIUM)
    if new_os and isinstance(new_os, dict):
        active_os = OSInstallation.query.filter_by(
            device_id=device.id,
            status=OsInstallationStatus.ACTIVE,
        ).first()
        if active_os:
            os_name_changed = new_os.get("name") and new_os.get("name") != active_os.os_name
            os_ver_changed = new_os.get("version") and new_os.get("version") != active_os.os_version
            if os_name_changed or os_ver_changed:
                evt = DeviceEvent(
                    device_id=device.id,
                    event_type=DeviceEventType.OS_CHANGED,
                    severity=EventSeverity.MEDIUM,
                    payload={
                        "old_os": f"{active_os.os_name} {active_os.os_version}",
                        "new_os": f"{new_os.get('name')} {new_os.get('version')}",
                    },
                    occurred_at=now,
                    created_at=now,
                )
                db.session.add(evt)
                events.append(evt)

    if events:
        db.session.commit()

    return events


def approve_hardware_change(device_identifier: str | int, admin_name: str) -> PhysicalDevice:
    """Admin approval of hardware changes: marks latest evidence snapshot trusted and restores status."""
    dev = (
        PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if isinstance(device_identifier, str)
        else db.session.get(PhysicalDevice, device_identifier)
    )
    if not dev:
        raise ValueError(f"Device {device_identifier} not found")

    latest_ev = (
        DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
        .order_by(DeviceIdentityEvidence.captured_at.desc())
        .first()
    )
    if latest_ev:
        latest_ev.trusted = True

    old_status = dev.status.value
    if dev.status == DeviceStatus.PENDING_REVERIFICATION:
        dev.status = DeviceStatus.ACTIVE

    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.HARDWARE_CHANGE_APPROVED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": old_status},
            new_value={"status": dev.status.value},
            metadata_json={"evidence_snapshot_id": latest_ev.id if latest_ev else None},
        )
    )
    db.session.commit()
    return dev


def pair_unclaimed_device(
    device_identifier: str | int,
    asset_identifier: str | int,
    admin_name: str,
) -> tuple[PhysicalDevice, Asset]:
    """Pair an unclaimed endpoint to an institutional asset."""
    dev = (
        PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if isinstance(device_identifier, str)
        else db.session.get(PhysicalDevice, device_identifier)
    )
    if not dev:
        raise ValueError(f"Device {device_identifier} not found")

    asset = (
        Asset.query.filter_by(asset_id=str(asset_identifier)).first()
        if isinstance(asset_identifier, str)
        else db.session.get(Asset, asset_identifier)
    )
    if not asset:
        raise ValueError(f"Asset {asset_identifier} not found")

    # Check if asset already has an active link
    existing_link = AssetDeviceLink.query.filter_by(
        asset_id=asset.id,
        relationship_status=RelationshipStatus.ACTIVE,
    ).first()
    if existing_link:
        raise ValueError(f"Asset {asset.asset_id} already has an active device link")

    now = datetime.now(UTC)
    link = AssetDeviceLink(
        asset_id=asset.id,
        device_id=dev.id,
        relationship_status=RelationshipStatus.ACTIVE,
        linked_at=now,
        linked_by=admin_name,
        reason="Admin paired unclaimed device",
    )
    db.session.add(link)

    dev.status = DeviceStatus.PENDING_VERIFICATION
    asset.lifecycle_status = AssetLifecycleStatus.PENDING_VERIFICATION

    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_LINKED,
            entity_type="link",
            entity_id=f"{asset.asset_id}:{dev.device_id}",
            new_value={"asset_id": asset.asset_id, "device_id": dev.device_id},
        )
    )
    db.session.commit()
    return dev, asset
