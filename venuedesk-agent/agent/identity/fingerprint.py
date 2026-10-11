"""Hardware identity canonicalization, HMAC hashing, and versioned SHA-256 fingerprinting."""
import hashlib
import hmac
import json
import re
from typing import Any

FINGERPRINT_VERSION = 1

PLACEHOLDERS: set[str] = {
    "",
    "none",
    "unknown",
    "default string",
    "to be filled by o.e.m.",
    "to be filled by o.e.m",
    "not specified",
    "0",
    "system serial number",
    "chassis serial number",
}

VIRTUAL_NIC_PATTERNS = [
    re.compile(r"^docker", re.IGNORECASE),
    re.compile(r"^veth", re.IGNORECASE),
    re.compile(r"^vmnet", re.IGNORECASE),
    re.compile(r"^vbox", re.IGNORECASE),
    re.compile(r"^lo$", re.IGNORECASE),
    re.compile(r"^loopback", re.IGNORECASE),
    re.compile(r"^tun", re.IGNORECASE),
    re.compile(r"^tap", re.IGNORECASE),
    re.compile(r"^wg", re.IGNORECASE),
    re.compile(r"^br-", re.IGNORECASE),
    re.compile(r"^virbr", re.IGNORECASE),
    re.compile(r"tether", re.IGNORECASE),
    re.compile(r"rndis", re.IGNORECASE),
    re.compile(r"hyper-v", re.IGNORECASE),
    re.compile(r"wsl", re.IGNORECASE),
]


def norm(v: Any) -> str | None:
    """Normalize string: strip whitespace, lowercase, collapse internal whitespace, check placeholders."""
    if v is None:
        return None
    s = " ".join(str(v).strip().lower().split())
    if not s or s in PLACEHOLDERS:
        return None
    # Check for all-zero or all-F or repeated dummy sequences (e.g. 00000000-0000-0000-0000-000000000000)
    non_sep = set(s.replace("-", "").replace(":", ""))
    if non_sep <= {"0"} or non_sep <= {"f"}:
        return None
    return s


def is_virtual_or_tether_nic(nic_name: str) -> bool:
    """Return True if the network interface name matches known virtual/tether patterns."""
    normalized = nic_name.strip().lower()
    return any(pattern.search(normalized) for pattern in VIRTUAL_NIC_PATTERNS)


def filter_nics(nics: list[Any] | None) -> list[str]:
    """Filter out virtual, container, and tethering network adapters."""
    if not nics:
        return []
    filtered = []
    for nic in nics:
        s = str(nic).strip()
        if s and not is_virtual_or_tether_nic(s):
            filtered.append(s)
    return filtered


def norm_list(items: list[Any] | None) -> list[str]:
    """Normalize list elements, drop missing/placeholder, sort alphabetically, and deduplicate."""
    if not items:
        return []
    return sorted({n for n in (norm(x) for x in items) if n is not None})


def compute_fingerprint(ev: dict[str, Any], version: int = FINGERPRINT_VERSION) -> str:
    """Compute deterministic SHA-256 fingerprint from canonical hardware evidence."""
    raw_nics = ev.get("nics", [])
    filtered_nics = filter_nics(raw_nics) if isinstance(raw_nics, list) else []

    canon = {
        "v": version,
        "machine_uuid": norm(ev.get("machine_uuid")),
        "bios_serial": norm(ev.get("bios_serial")),
        "motherboard_serial": norm(ev.get("motherboard_serial")),
        "cpu": norm(ev.get("cpu")),
        "gpus": norm_list(ev.get("gpus")),
        "disks": norm_list(ev.get("disks")),
        "nics": norm_list(filtered_nics),
    }
    encoded = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def field_hash(salt: bytes, value: Any) -> str | None:
    """Compute HMAC-SHA256 for a sensitive hardware field value using the deployment salt."""
    n = norm(value)
    if not n:
        return None
    return hmac.new(salt, n.encode("utf-8"), hashlib.sha256).hexdigest()
