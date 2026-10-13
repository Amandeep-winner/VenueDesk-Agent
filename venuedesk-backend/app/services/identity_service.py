"""Identity reconciliation, diffing, similarity scoring, and decision engine."""
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from app.extensions import db
from app.models import (
    ActorType,
    Asset,
    AssetDeviceLink,
    AssetLifecycleStatus,
    AssetVerificationStatus,
    AuditAction,
    AuditLog,
    DeviceEvent,
    DeviceEventType,
    DeviceIdentityEvidence,
    DeviceInventory,
    DeviceRecoveryRequest,
    DeviceStatus,
    EnrollmentToken,
    EventSeverity,
    EvidenceSource,
    FieldMatchResult,
    HardwareChangeRecord,
    OsFamily,
    OSInstallation,
    OsInstallationStatus,
    PhysicalDevice,
    RelationshipStatus,
    UserRole,
    Verification,
    VerificationMethod,
)

logger = logging.getLogger(__name__)


class LinkConflictError(Exception):
    """Raised when an asset or device already has an active link and reassignment is not permitted."""

    def __init__(self, message: str = "Link conflict: device or asset already linked"):
        super().__init__(message)
        self.status_code = 409
        self.error_code = "link_conflict"



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


PLACEHOLDERS = {
    "",
    "none",
    "unknown",
    "null",
    "default string",
    "to be filled by o.e.m.",
    "to be filled by o.e.m",
    "not specified",
    "0",
    "system serial number",
    "chassis serial number",
}


def _norm(val: Any) -> str | None:
    """Normalize string: strip, lowercase, collapse whitespace, check placeholders."""
    if val is None:
        return None
    s = " ".join(str(val).strip().lower().split())
    if not s or s in PLACEHOLDERS:
        return None
    non_sep = set(s.replace("-", "").replace(":", ""))
    if non_sep <= {"0"} or non_sep <= {"f"}:
        return None
    return s


def compare_field(val_a: Any, val_b: Any) -> FieldMatchResult:
    """Compare two hardware values. None == None is never evidence of sameness."""
    norm_a = _norm(val_a)
    norm_b = _norm(val_b)
    if norm_a is None or norm_b is None:
        return FieldMatchResult.UNKNOWN
    if norm_a == norm_b:
        return FieldMatchResult.MATCH
    return FieldMatchResult.MISMATCH


@dataclass
class ChangeRecord:
    field: str
    previous_value: Any
    new_value: Any
    severity: EventSeverity
    requires_approval: bool
    event_type: DeviceEventType
    decision: str


DEFAULT_IDENTITY_SEVERITY_POLICY = {
    "ip_addresses": {"severity": EventSeverity.LOW, "requires_approval": False, "event_type": DeviceEventType.IP_CHANGED},
    "hostname": {"severity": EventSeverity.LOW, "requires_approval": False, "event_type": DeviceEventType.HOSTNAME_CHANGED},
    "ram_total_mb": {"severity": EventSeverity.LOW, "requires_approval": False, "event_type": DeviceEventType.RAM_CHANGED},
    "gpus": {"severity": EventSeverity.LOW, "requires_approval": False, "event_type": DeviceEventType.GPU_CHANGED},
    "disks": {"severity": EventSeverity.MEDIUM, "requires_approval": False, "event_type": DeviceEventType.DISK_CHANGED},
    "mac_addresses": {"severity": EventSeverity.MEDIUM, "requires_approval": False, "event_type": DeviceEventType.NIC_CHANGED},
    "fingerprint_version": {"severity": EventSeverity.INFO, "requires_approval": False, "event_type": DeviceEventType.FINGERPRINT_MIGRATED},
    "motherboard_serial": {"severity": EventSeverity.HIGH, "requires_approval": True, "event_type": DeviceEventType.MOTHERBOARD_CHANGED},
    "strong_anchors_conflict": {"severity": EventSeverity.HIGH, "requires_approval": True, "event_type": DeviceEventType.IDENTITY_CHANGE_DETECTED},
}


def classify_change(
    prev_trusted: DeviceIdentityEvidence | dict[str, Any] | None,
    current: dict[str, Any],
    inventory_prev: DeviceInventory | dict[str, Any] | None = None,
    inventory_curr: dict[str, Any] | None = None,
    source: EvidenceSource = EvidenceSource.AGENT_IDENTITY,
    severity_policy: dict[str, Any] | None = None,
) -> tuple[list[ChangeRecord], str, bool]:
    """Classify differences between prior trusted state and current observations per spec §4.6."""
    policy = severity_policy or DEFAULT_IDENTITY_SEVERITY_POLICY
    records: list[ChangeRecord] = []
    decision = IdentityDecision.SAME_DEVICE.value
    needs_approval = False

    prev_dict: dict[str, Any] = {}
    if prev_trusted is not None:
        if isinstance(prev_trusted, dict):
            prev_dict = prev_trusted
        else:
            prev_dict = {
                "machine_uuid_hash": prev_trusted.machine_uuid_hash,
                "motherboard_serial_hash": prev_trusted.motherboard_serial_hash,
                "bios_serial_hash": prev_trusted.bios_serial_hash,
                "cpu_signature": prev_trusted.cpu_signature,
                "gpu_signature": prev_trusted.gpu_signature,
                "disk_identity_hash": prev_trusted.disk_identity_hash,
                "network_identity_hash": prev_trusted.network_identity_hash,
                "tpm_identity": prev_trusted.tpm_identity,
                "fingerprint": prev_trusted.fingerprint,
                "fingerprint_version": getattr(prev_trusted, "fingerprint_version", 1),
            }

    # 1. Fingerprint algorithm version upgraded
    prev_fp_ver = prev_dict.get("fingerprint_version", 1)
    curr_fp_ver = current.get("fingerprint_version", 1)
    if prev_fp_ver and curr_fp_ver and prev_fp_ver != curr_fp_ver:
        cfg = policy.get("fingerprint_version", {"severity": EventSeverity.INFO, "requires_approval": False})
        records.append(
            ChangeRecord(
                field="fingerprint_version",
                previous_value=str(prev_fp_ver),
                new_value=str(curr_fp_ver),
                severity=cfg["severity"],
                requires_approval=cfg["requires_approval"],
                event_type=DeviceEventType.FINGERPRINT_MIGRATED,
                decision="FINGERPRINT_MIGRATED",
            )
        )

    # 2. Check strong anchors (machine_uuid, motherboard_serial, bios_serial, tpm_identity)
    strong_anchors = [
        ("machine_uuid_hash", ["machine_uuid_hash", "machine_uuid"]),
        ("motherboard_serial_hash", ["motherboard_serial_hash", "motherboard_serial"]),
        ("bios_serial_hash", ["bios_serial_hash", "bios_serial"]),
        ("tpm_identity", ["tpm_identity"]),
    ]
    mismatches = 0
    mb_mismatched = False
    tpm_mismatched = False

    for attr, keys in strong_anchors:
        o_val = prev_dict.get(attr)
        n_val = None
        for k in keys:
            if current.get(k) is not None:
                n_val = current[k]
                break
        res = compare_field(o_val, n_val)
        if res == FieldMatchResult.MISMATCH:
            mismatches += 1
            if attr == "motherboard_serial_hash":
                mb_mismatched = True
            elif attr == "tpm_identity":
                tpm_mismatched = True

    if mb_mismatched:
        cfg = policy.get("motherboard_serial", {"severity": EventSeverity.HIGH, "requires_approval": True})
        records.append(
            ChangeRecord(
                field="motherboard_serial_hash",
                previous_value=str(prev_dict.get("motherboard_serial_hash")),
                new_value=str(current.get("motherboard_serial_hash") or current.get("motherboard_serial")),
                severity=cfg["severity"],
                requires_approval=cfg["requires_approval"],
                event_type=DeviceEventType.MOTHERBOARD_CHANGED,
                decision=IdentityDecision.PENDING_REVERIFICATION.value,
            )
        )
        decision = IdentityDecision.PENDING_REVERIFICATION.value
        needs_approval = True

    if tpm_mismatched:
        cfg = policy.get("tpm_identity", {"severity": EventSeverity.HIGH, "requires_approval": True})
        records.append(
            ChangeRecord(
                field="tpm_identity",
                previous_value=str(prev_dict.get("tpm_identity")),
                new_value=str(current.get("tpm_identity")),
                severity=cfg["severity"],
                requires_approval=cfg["requires_approval"],
                event_type=DeviceEventType.TPM_CHANGED,
                decision=IdentityDecision.PENDING_REVERIFICATION.value,
            )
        )
        decision = IdentityDecision.PENDING_REVERIFICATION.value
        needs_approval = True

    if mismatches >= 2:
        cfg = policy.get("strong_anchors_conflict", {"severity": EventSeverity.HIGH, "requires_approval": True})
        records.append(
            ChangeRecord(
                field="strong_anchors_conflict",
                previous_value=f"{mismatches} anchors mismatched",
                new_value="conflicting",
                severity=cfg["severity"],
                requires_approval=cfg["requires_approval"],
                event_type=DeviceEventType.IDENTITY_CHANGE_DETECTED,
                decision=IdentityDecision.PENDING_REVERIFICATION.value,
            )
        )
        decision = IdentityDecision.PENDING_REVERIFICATION.value
        needs_approval = True

    # 3. Inventory changes (if provided)
    if inventory_prev and inventory_curr:
        inv_p = inventory_prev if isinstance(inventory_prev, dict) else {
            "hostname": inventory_prev.hostname,
            "ip_addresses": inventory_prev.ip_addresses or [],
            "mac_addresses": inventory_prev.mac_addresses or [],
            "ram_total_mb": inventory_prev.ram_total_mb,
            "gpus": inventory_prev.gpus or [],
            "disks": inventory_prev.disks or [],
        }

        # IP changed
        old_ips = sorted(inv_p.get("ip_addresses") or [])
        new_ips = sorted(inventory_curr.get("ip_addresses") or [])
        if old_ips and new_ips and old_ips != new_ips:
            cfg = policy.get("ip_addresses", {"severity": EventSeverity.LOW, "requires_approval": False})
            records.append(ChangeRecord("ip_addresses", old_ips, new_ips, cfg["severity"], cfg["requires_approval"], DeviceEventType.IP_CHANGED, "IP_CHANGED"))

        # Hostname changed
        old_h = inv_p.get("hostname")
        new_h = inventory_curr.get("hostname")
        if old_h and new_h and old_h != new_h and old_h != "unknown":
            cfg = policy.get("hostname", {"severity": EventSeverity.LOW, "requires_approval": False})
            records.append(ChangeRecord("hostname", old_h, new_h, cfg["severity"], cfg["requires_approval"], DeviceEventType.HOSTNAME_CHANGED, "HOSTNAME_CHANGED"))

        # RAM changed
        old_ram = inv_p.get("ram_total_mb")
        new_ram = inventory_curr.get("ram_total_mb")
        if old_ram and new_ram and old_ram != new_ram:
            cfg = policy.get("ram_total_mb", {"severity": EventSeverity.LOW, "requires_approval": False})
            records.append(ChangeRecord("ram_total_mb", old_ram, new_ram, cfg["severity"], cfg["requires_approval"], DeviceEventType.RAM_CHANGED, "RAM_CHANGED"))

        # GPU changed
        old_gpus = sorted(inv_p.get("gpus") or [])
        new_gpus = sorted(inventory_curr.get("gpus") or [])
        if old_gpus and new_gpus and old_gpus != new_gpus:
            cfg = policy.get("gpus", {"severity": EventSeverity.LOW, "requires_approval": False})
            records.append(ChangeRecord("gpus", old_gpus, new_gpus, cfg["severity"], cfg["requires_approval"], DeviceEventType.GPU_CHANGED, "GPU_CHANGED"))

        # Disks changed
        old_disks = sorted(inv_p.get("disks") or [])
        new_disks = sorted(inventory_curr.get("disks") or [])
        if old_disks and new_disks and old_disks != new_disks:
            cfg = policy.get("disks", {"severity": EventSeverity.MEDIUM, "requires_approval": False})
            records.append(ChangeRecord("disks", old_disks, new_disks, cfg["severity"], cfg["requires_approval"], DeviceEventType.DISK_CHANGED, "DISK_CHANGED"))

        # NICs changed
        old_macs = sorted(inv_p.get("mac_addresses") or [])
        new_macs = sorted(inventory_curr.get("mac_addresses") or [])
        if old_macs and new_macs and old_macs != new_macs:
            cfg = policy.get("mac_addresses", {"severity": EventSeverity.MEDIUM, "requires_approval": False})
            records.append(ChangeRecord("mac_addresses", old_macs, new_macs, cfg["severity"], cfg["requires_approval"], DeviceEventType.NIC_CHANGED, "NIC_CHANGED"))

    return records, decision, needs_approval


def compare_fingerprints(fp_a: str | None, ver_a: int, fp_b: str | None, ver_b: int) -> bool:
    """Compare fingerprints only within the exact same algorithm version."""
    if not fp_a or not fp_b:
        return False
    if ver_a != ver_b:
        return False
    return fp_a == fp_b


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

        res = compare_field(val_a, val_b)
        if res == FieldMatchResult.UNKNOWN:
            continue

        total_possible_weight += weight
        if res == FieldMatchResult.MATCH:
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
        ref_val = getattr(ref_ev, ref_attr, None)
        obs_val = None
        for k in obs_keys:
            if obs_ev.get(k) is not None:
                obs_val = obs_ev[k]
                break

        if compare_field(ref_val, obs_val) == FieldMatchResult.MATCH:
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
    ref_ev = (
        DeviceIdentityEvidence.query.filter(
            DeviceIdentityEvidence.device_id == device.id,
            DeviceIdentityEvidence.trusted.is_(True),
        )
        .order_by(DeviceIdentityEvidence.captured_at.desc())
        .first()
    )
    if not ref_ev:
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

    records, _decision, needs_approval = classify_change(
        prev_trusted=ref_ev,
        current=new_evidence,
        source=EvidenceSource.AGENT_IDENTITY,
    )

    for rec in records:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=rec.event_type,
            severity=rec.severity,
            payload={"field": rec.field, "old": rec.previous_value, "new": rec.new_value},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

        hcr = HardwareChangeRecord(
            device_id=device.id,
            occurred_at=now,
            field=rec.field,
            previous_value=str(rec.previous_value)[:255] if rec.previous_value is not None else None,
            new_value=str(rec.new_value)[:255] if rec.new_value is not None else None,
            evidence_source=EvidenceSource.AGENT_IDENTITY,
            reconciliation_decision=rec.decision,
            requires_approval=rec.requires_approval,
        )
        db.session.add(hcr)

    if needs_approval:
        device.status = DeviceStatus.PENDING_REVERIFICATION

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

    records, _decision, _needs_approval = classify_change(
        prev_trusted=None,
        current={},
        inventory_prev=inv,
        inventory_curr=new_inventory,
        source=EvidenceSource.AGENT_INVENTORY,
    )

    for rec in records:
        evt = DeviceEvent(
            device_id=device.id,
            event_type=rec.event_type,
            severity=rec.severity,
            payload={"field": rec.field, "old": rec.previous_value, "new": rec.new_value},
            occurred_at=now,
            created_at=now,
        )
        db.session.add(evt)
        events.append(evt)

        # In spec: RAM / GPU changed -> HARDWARE_CHANGED + RAM_CHANGED / GPU_CHANGED (LOW)
        if rec.field in ("ram_total_mb", "gpus"):
            hw_evt = DeviceEvent(
                device_id=device.id,
                event_type=DeviceEventType.HARDWARE_CHANGED,
                severity=EventSeverity.LOW,
                payload={"field": rec.field, "old": rec.previous_value, "new": rec.new_value},
                occurred_at=now,
                created_at=now,
            )
            db.session.add(hw_evt)
            events.append(hw_evt)

        hcr = HardwareChangeRecord(
            device_id=device.id,
            occurred_at=now,
            field=rec.field,
            previous_value=str(rec.previous_value)[:255] if rec.previous_value is not None else None,
            new_value=str(rec.new_value)[:255] if rec.new_value is not None else None,
            evidence_source=EvidenceSource.AGENT_INVENTORY,
            reconciliation_decision=rec.decision,
            requires_approval=rec.requires_approval,
        )
        db.session.add(hcr)

    # 7. OS changed -> OS_CHANGED (MEDIUM)
    if new_os and isinstance(new_os, dict):
        os_inst_id = new_os.get("os_installation_id")
        active_os = None
        if os_inst_id:
            active_os = OSInstallation.query.filter_by(
                device_id=device.id,
                os_installation_id=os_inst_id,
            ).first()
        if not active_os:
            raw_fam = (new_os.get("family") or "OTHER").upper()
            try:
                os_fam = OsFamily(raw_fam)
                active_os = OSInstallation.query.filter_by(
                    device_id=device.id,
                    os_family=os_fam,
                    status=OsInstallationStatus.ACTIVE,
                ).first()
            except ValueError:
                pass
        if not active_os:
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

    now = datetime.now(UTC)
    old_status = dev.status.value
    if dev.status == DeviceStatus.PENDING_REVERIFICATION:
        dev.status = DeviceStatus.ACTIVE

    # Update pending hardware change records requiring approval
    pending_records = HardwareChangeRecord.query.filter_by(
        device_id=dev.id,
        requires_approval=True,
        approved_at=None,
    ).all()
    for prec in pending_records:
        prec.approved_by = admin_name
        prec.approved_at = now

    audit_entry = AuditLog(
        actor_id=admin_name,
        actor_type=ActorType.USER,
        action=AuditAction.HARDWARE_CHANGE_APPROVED,
        entity_type="device",
        entity_id=dev.device_id,
        old_value={"status": old_status},
        new_value={"status": dev.status.value},
        metadata_json={"evidence_snapshot_id": latest_ev.id if latest_ev else None},
    )
    db.session.add(audit_entry)
    db.session.flush()

    for prec in pending_records:
        prec.audit_log_id = audit_entry.id

    db.session.commit()
    return dev


def pair_device(
    device_identifier: str | int,
    asset_identifier: str | int,
    admin_name: str = "system",
    actor_role: UserRole | str | None = None,
    reassignment: bool = False,
    reason: str | None = None,
    commit: bool = True,
    _inject_failure: bool = False,
    _caller: str = "admin",
) -> tuple[PhysicalDevice, Asset, AssetDeviceLink]:
    """Pair an endpoint to an institutional asset with strict concurrency and state checks."""
    bind = db.session.get_bind()
    is_pg = bind.dialect.name == "postgresql"
    is_sqlite = bind.dialect.name == "sqlite"

    try:
        if is_sqlite:
            try:
                db.session.execute(text("BEGIN IMMEDIATE"))
            except (OperationalError, db.exc.SQLAlchemyError) as exc:
                logger.debug("SQLite immediate lock skipped: %s", exc)

        # 1. Load device with row lock
        dev_query = (
            PhysicalDevice.query.filter_by(device_id=str(device_identifier))
            if isinstance(device_identifier, str)
            else PhysicalDevice.query.filter_by(id=device_identifier)
        )
        if is_pg:
            dev_query = dev_query.with_for_update()
        dev = dev_query.first()
        if not dev:
            raise ValueError(f"Device {device_identifier} not found")

        # Load asset with row lock
        asset_query = (
            Asset.query.filter_by(asset_id=str(asset_identifier))
            if isinstance(asset_identifier, str)
            else Asset.query.filter_by(id=asset_identifier)
        )
        if is_pg:
            asset_query = asset_query.with_for_update()
        asset = asset_query.first()
        if not asset:
            raise ValueError(f"Asset {asset_identifier} not found")

        # 2. Validate lifecycle status
        if asset.lifecycle_status in (AssetLifecycleStatus.RETIRED, AssetLifecycleStatus.DISPOSED):
            raise ValueError(f"Asset {asset.asset_id} is {asset.lifecycle_status.value} and cannot be paired")

        if dev.status in (DeviceStatus.REVOKED, DeviceStatus.RETIRED):
            raise ValueError(f"Device {dev.device_id} is {dev.status.value} and cannot be paired")

        if _caller != "enrollment":
            allowed_statuses = (
                DeviceStatus.UNCLAIMED,
                DeviceStatus.PENDING_REVERIFICATION,
                DeviceStatus.PENDING_VERIFICATION,
                DeviceStatus.ENROLLING,
            )
            if not reassignment and dev.status not in allowed_statuses:
                raise ValueError(f"Device {dev.device_id} status {dev.status.value} does not permit initial pairing")

        # 3. Look up active links
        existing_asset_link = AssetDeviceLink.query.filter_by(
            asset_id=asset.id,
            relationship_status=RelationshipStatus.ACTIVE,
        ).first()

        existing_device_link = AssetDeviceLink.query.filter_by(
            device_id=dev.id,
            relationship_status=RelationshipStatus.ACTIVE,
        ).first()

        has_existing = (existing_asset_link is not None) or (existing_device_link is not None)

        # 4. Conflict check
        if has_existing:
            role_val = actor_role.value if hasattr(actor_role, "value") else str(actor_role or "")
            is_infra_admin = role_val == UserRole.INFRA_ADMIN.value or role_val == "infra_admin"
            if not reassignment or not (reason and reason.strip()) or not is_infra_admin:
                raise LinkConflictError("Link conflict: device or asset already has an active link")

            # 5. Reassignment authorized: close old link(s)
            now = datetime.now(UTC)
            if existing_asset_link:
                existing_asset_link.relationship_status = RelationshipStatus.CLOSED
                existing_asset_link.unlinked_at = now
                existing_asset_link.reason = reason
                db.session.add(
                    AuditLog(
                        actor_id=admin_name,
                        actor_type=ActorType.USER if admin_name != "system" else ActorType.SYSTEM,
                        action=AuditAction.DEVICE_UNLINKED,
                        entity_type="link",
                        entity_id=f"{asset.asset_id}:{existing_asset_link.device_id}",
                        old_value={"relationship_status": "ACTIVE"},
                        new_value={"relationship_status": "CLOSED", "reason": reason},
                    )
                )
            if existing_device_link and existing_device_link != existing_asset_link:
                existing_device_link.relationship_status = RelationshipStatus.CLOSED
                existing_device_link.unlinked_at = now
                existing_device_link.reason = reason
                db.session.add(
                    AuditLog(
                        actor_id=admin_name,
                        actor_type=ActorType.USER if admin_name != "system" else ActorType.SYSTEM,
                        action=AuditAction.DEVICE_UNLINKED,
                        entity_type="link",
                        entity_id=f"{existing_device_link.asset_id}:{dev.device_id}",
                        old_value={"relationship_status": "ACTIVE"},
                        new_value={"relationship_status": "CLOSED", "reason": reason},
                    )
                )
            db.session.flush()

        # 6. Create new ACTIVE link
        now = datetime.now(UTC)
        link = AssetDeviceLink(
            asset_id=asset.id,
            device_id=dev.id,
            relationship_status=RelationshipStatus.ACTIVE,
            linked_at=now,
            linked_by=admin_name,
            reason=reason or ("Admin paired unclaimed device" if admin_name != "system" else "asset-scoped enrollment token"),
        )
        db.session.add(link)

        dev.status = DeviceStatus.PENDING_VERIFICATION
        asset.lifecycle_status = AssetLifecycleStatus.PENDING_VERIFICATION

        db.session.add(
            AuditLog(
                actor_id=admin_name,
                actor_type=ActorType.USER if admin_name != "system" else ActorType.SYSTEM,
                action=AuditAction.DEVICE_LINKED,
                entity_type="link",
                entity_id=f"{asset.asset_id}:{dev.device_id}",
                new_value={"asset_id": asset.asset_id, "device_id": dev.device_id, "reason": link.reason},
            )
        )

        if _inject_failure:
            raise RuntimeError("Injected failure mid-transaction for test")

        if commit:
            db.session.commit()
        else:
            db.session.flush()

        return dev, asset, link

    except (IntegrityError, OperationalError) as e:
        db.session.rollback()
        raise LinkConflictError("Link conflict: active link already exists") from e
    except Exception:
        db.session.rollback()
        raise


def pair_unclaimed_device(
    device_identifier: str | int,
    asset_identifier: str | int,
    admin_name: str,
    actor_role: UserRole | str | None = UserRole.INFRA_ADMIN,
) -> tuple[PhysicalDevice, Asset]:
    """Pair an unclaimed endpoint to an institutional asset (compatibility wrapper)."""
    dev, asset, _ = pair_device(
        device_identifier=device_identifier,
        asset_identifier=asset_identifier,
        admin_name=admin_name,
        actor_role=actor_role,
        reassignment=False,
    )
    return dev, asset



def approve_device_recovery(
    device_identifier: str | int,
    admin_name: str,
) -> tuple[PhysicalDevice, DeviceRecoveryRequest]:
    """Approve pending OS reinstall recovery request, rotate public key, and activate new OS."""
    dev = (
        PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if isinstance(device_identifier, str)
        else db.session.get(PhysicalDevice, device_identifier)
    )
    if not dev:
        raise ValueError(f"Device {device_identifier} not found")

    rec_req = (
        DeviceRecoveryRequest.query.filter_by(device_id=dev.id, status="PENDING")
        .order_by(DeviceRecoveryRequest.created_at.desc())
        .first()
    )
    if not rec_req:
        raise ValueError(f"No pending recovery request found for device {dev.device_id}")

    now = datetime.now(UTC)

    os_data = rec_req.new_os_info or {}
    raw_family = (os_data.get("family") or "OTHER").upper()
    try:
        os_fam = OsFamily(raw_family)
    except ValueError:
        os_fam = OsFamily.OTHER

    # 1. Rotate credentials
    old_cred_ver = dev.credential_version or 1
    new_cred_ver = old_cred_ver + 1
    dev.device_public_key = rec_req.new_public_key
    dev.credential_version = new_cred_ver
    dev.status = DeviceStatus.ACTIVE
    dev.last_seen = now

    new_os_inst_id = (
        rec_req.new_os_installation_id
        or os_data.get("os_installation_id")
        or rec_req.new_agent_instance_id
        or "unknown"
    )

    # 2. Archive active OS installations for this OS family/slot (in dual boot, other OS remains ACTIVE)
    matching_active_os = OSInstallation.query.filter_by(
        device_id=dev.id,
        os_family=os_fam,
        status=OsInstallationStatus.ACTIVE,
    ).all()

    prior_os_inst_ids = set()
    for eos in matching_active_os:
        eos.status = OsInstallationStatus.HISTORICAL
        if eos.os_installation_id:
            prior_os_inst_ids.add(eos.os_installation_id)
        if eos.agent_instance_id:
            prior_os_inst_ids.add(eos.agent_instance_id)

    if not matching_active_os:
        all_active_os = OSInstallation.query.filter_by(
            device_id=dev.id,
            status=OsInstallationStatus.ACTIVE,
        ).all()
        if len(all_active_os) == 1:
            for eos in all_active_os:
                eos.status = OsInstallationStatus.HISTORICAL
                if eos.os_installation_id:
                    prior_os_inst_ids.add(eos.os_installation_id)

    # 3. Revoke previous credentials for the reinstalled slot
    from app.models.device import DeviceCredential
    if prior_os_inst_ids:
        prev_creds = DeviceCredential.query.filter(
            DeviceCredential.device_id == dev.id,
            DeviceCredential.os_installation_id.in_(prior_os_inst_ids),
            DeviceCredential.status == "ACTIVE",
        ).all()
        for pcred in prev_creds:
            pcred.status = "REVOKED"
            pcred.revoked_at = now
    else:
        all_active_creds = DeviceCredential.query.filter_by(device_id=dev.id, status="ACTIVE").all()
        if len(all_active_creds) <= 1:
            for pcred in all_active_creds:
                pcred.status = "REVOKED"
                pcred.revoked_at = now

    # 4. Register new credential in device_credentials
    new_cred = DeviceCredential(
        device_id=dev.id,
        os_installation_id=new_os_inst_id,
        public_key=rec_req.new_public_key,
        credential_version=new_cred_ver,
        status="ACTIVE",
        created_at=now,
    )
    db.session.add(new_cred)

    # 5. Create new ACTIVE OSInstallation
    os_name = os_data.get("name", "Unknown")
    os_version = os_data.get("version", "Unknown")
    arch = os_data.get("architecture", "Unknown")
    machine_id_hash = os_data.get("os_machine_id_hash", "none")

    new_os = OSInstallation(
        device_id=dev.id,
        os_installation_id=new_os_inst_id,
        os_family=os_fam,
        os_name=os_name,
        os_version=os_version,
        architecture=arch,
        os_machine_id_hash=machine_id_hash,
        agent_instance_id=rec_req.new_agent_instance_id,
        status=OsInstallationStatus.ACTIVE,
        first_seen=now,
        last_seen=now,
    )
    db.session.add(new_os)

    # 3. Update inventory if provided
    if rec_req.new_inventory:
        inv = dev.inventory
        if not inv:
            inv = DeviceInventory(device_id=dev.id, hostname="unknown", agent_version="0.1.0")
            db.session.add(inv)
        inv_data = rec_req.new_inventory
        inv.hostname = inv_data.get("hostname", inv.hostname)
        inv.ip_addresses = inv_data.get("ip_addresses", inv.ip_addresses)
        inv.mac_addresses = inv_data.get("mac_addresses", inv.mac_addresses)
        inv.cpu_model = inv_data.get("cpu_model", inv.cpu_model)
        inv.cpu_cores = inv_data.get("cpu_cores", inv.cpu_cores)
        inv.ram_total_mb = inv_data.get("ram_total_mb", inv.ram_total_mb)
        inv.gpus = inv_data.get("gpus", inv.gpus)
        inv.disks = inv_data.get("disks", inv.disks)
        inv.os_summary = inv_data.get("os_summary", inv.os_summary)
        inv.bios_version = inv_data.get("bios_version", inv.bios_version)
        inv.updated_at = now

    # 4. Record new evidence snapshot or trust latest
    if rec_req.new_evidence:
        ev_data = rec_req.new_evidence
        ev_row = DeviceIdentityEvidence(
            device_id=dev.id,
            machine_uuid_hash=ev_data.get("machine_uuid_hash"),
            bios_serial_hash=ev_data.get("bios_serial_hash"),
            motherboard_serial_hash=ev_data.get("motherboard_serial_hash"),
            cpu_signature=ev_data.get("cpu_signature"),
            gpu_signature=ev_data.get("gpu_signature"),
            disk_identity_hash=ev_data.get("disk_identity_hash"),
            network_identity_hash=ev_data.get("network_identity_hash"),
            tpm_identity=ev_data.get("tpm_identity"),
            fingerprint=ev_data.get("fingerprint", "unknown"),
            fingerprint_version=ev_data.get("fingerprint_version", 1),
            captured_at=now,
            evidence_version=1,
            trusted=True,
        )
        db.session.add(ev_row)
    else:
        latest_ev = (
            DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
            .order_by(DeviceIdentityEvidence.captured_at.desc())
            .first()
        )
        if latest_ev:
            latest_ev.trusted = True

    # 5. Resolve recovery request
    rec_req.status = "APPROVED"
    rec_req.resolved_at = now
    rec_req.resolved_by = admin_name

    # 6. Audit log
    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.CREDENTIAL_ROTATED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"credential_version": old_cred_ver},
            new_value={"credential_version": dev.credential_version, "status": dev.status.value},
            metadata_json={"recovery_request_id": rec_req.id},
        )
    )
    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.HARDWARE_CHANGE_APPROVED,
            entity_type="device",
            entity_id=dev.device_id,
            old_value={"status": DeviceStatus.PENDING_REVERIFICATION.value},
            new_value={"status": dev.status.value, "os_installation_id": new_os_inst_id},
            metadata_json={"recovery_request_id": rec_req.id, "reason": rec_req.reason or "Admin approved recovery"},
        )
    )
    db.session.commit()
    return dev, rec_req


def verify_device_physical(
    device_identifier: str | int,
    admin_name: str,
    verification_method: str = "ADMIN_CONFIRMATION",
    observed_asset_tag: str | None = None,
    observed_serial: str | None = None,
    observed_location: str | None = None,
    notes: str | None = None,
) -> tuple[PhysicalDevice, Asset | None, Verification]:
    """Verify endpoint-to-asset physical continuity, update verification record, trusted snapshot, and asset status."""
    dev = (
        PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if isinstance(device_identifier, str)
        else db.session.get(PhysicalDevice, device_identifier)
    )
    if not dev:
        raise ValueError(f"Device {device_identifier} not found")

    try:
        method_enum = VerificationMethod(verification_method.upper())
    except (ValueError, KeyError, AttributeError):
        method_enum = VerificationMethod.ADMIN_CONFIRMATION

    now = datetime.now(UTC)

    # 1. Create verification audit record
    ver = Verification(
        device_id=dev.id,
        verified_by=admin_name,
        verification_method=method_enum,
        observed_asset_tag=observed_asset_tag,
        observed_serial=observed_serial,
        observed_location=observed_location,
        notes=notes,
        verified_at=now,
    )
    db.session.add(ver)
    db.session.flush()

    # 2. Update active asset link and asset status if linked
    active_link = AssetDeviceLink.query.filter_by(
        device_id=dev.id,
        relationship_status=RelationshipStatus.ACTIVE,
    ).first()

    asset = None
    if active_link:
        active_link.verification_id = ver.id
        asset = active_link.asset
        asset.verification_status = AssetVerificationStatus.VERIFIED
        asset.lifecycle_status = AssetLifecycleStatus.IN_SERVICE

    # 3. Update device state and trusted evidence snapshot
    dev.last_verified_at = now
    dev.status = DeviceStatus.ACTIVE

    latest_ev = (
        DeviceIdentityEvidence.query.filter_by(device_id=dev.id)
        .order_by(DeviceIdentityEvidence.captured_at.desc())
        .first()
    )
    if latest_ev:
        latest_ev.trusted = True

    # 4. Audit log
    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.ASSET_VERIFIED,
            entity_type="device",
            entity_id=dev.device_id,
            new_value={"verification_id": ver.id, "method": method_enum.value},
            metadata_json={"asset_id": asset.asset_id if asset else None},
        )
    )
    db.session.commit()
    return dev, asset, ver


def replace_device_endpoint(
    device_identifier: str | int,
    admin_name: str,
    reason: str = "Endpoint hardware/motherboard replacement",
) -> tuple[PhysicalDevice, Asset, str, EnrollmentToken]:
    """Motherboard replacement workflow: closes old device link, retires old device, and creates re-pairing token for same asset."""
    dev = (
        PhysicalDevice.query.filter_by(device_id=str(device_identifier)).first()
        if isinstance(device_identifier, str)
        else db.session.get(PhysicalDevice, device_identifier)
    )
    if not dev:
        raise ValueError(f"Device {device_identifier} not found")

    active_link = AssetDeviceLink.query.filter_by(
        device_id=dev.id,
        relationship_status=RelationshipStatus.ACTIVE,
    ).first()
    if not active_link:
        raise ValueError(f"Device {dev.device_id} has no active asset link to replace")

    asset = active_link.asset
    now = datetime.now(UTC)

    # 1. Close old link
    active_link.relationship_status = RelationshipStatus.CLOSED
    active_link.unlinked_at = now
    active_link.reason = reason

    # 2. Retire old device
    dev.status = DeviceStatus.RETIRED

    # 3. Audit unlinking
    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.DEVICE_UNLINKED,
            entity_type="link",
            entity_id=f"{asset.asset_id}:{dev.device_id}",
            new_value={"relationship_status": "CLOSED", "reason": reason},
        )
    )

    # 4. Generate new pairing token for the same asset
    from app.security.tokens import create_token_for_asset
    raw_token, token_obj = create_token_for_asset(asset.id, created_by=admin_name)

    # 5. Audit token creation
    db.session.add(
        AuditLog(
            actor_id=admin_name,
            actor_type=ActorType.USER,
            action=AuditAction.TOKEN_CREATED,
            entity_type="token",
            entity_id=str(token_obj.id),
            new_value={"asset_id": asset.asset_id},
        )
    )

    db.session.commit()
    return dev, asset, raw_token, token_obj

