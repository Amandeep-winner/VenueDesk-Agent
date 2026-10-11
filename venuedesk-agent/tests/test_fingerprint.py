"""Unit tests for identity fingerprinting, canonicalization, and HMAC hashing."""
from agent.identity.evidence import IdentityEvidence
from agent.identity.fingerprint import (
    compute_fingerprint,
    field_hash,
    filter_nics,
    is_virtual_or_tether_nic,
    norm,
    norm_list,
)


def test_normalization_placeholders():
    assert norm(None) is None
    assert norm("") is None
    assert norm("None") is None
    assert norm("unknown") is None
    assert norm("To Be Filled By O.E.M.") is None
    assert norm("Default string") is None
    assert norm("0") is None
    assert norm("00000000-0000-0000-0000-000000000000") is None
    assert norm("ffffffff-ffff-ffff-ffff-ffffffffffff") is None
    assert norm("System Serial Number") is None


def test_normalization_casing_and_whitespace():
    assert norm("  Intel(R)   Core(TM)  i7-7600U  ") == "intel(r) core(tm) i7-7600u"
    assert norm("XYZ-12345-ABC") == "xyz-12345-abc"


def test_virtual_nic_filtering():
    virtual_names = [
        "docker0",
        "veth39a8c1",
        "vmnet1",
        "vboxnet0",
        "lo",
        "loopback",
        "tun0",
        "tap1",
        "wg0",
        "br-lan",
        "virbr0",
        "rndis0",
        "usb-tethering",
        "Hyper-V Virtual Ethernet",
        "vEthernet (WSL)",
    ]
    for name in virtual_names:
        assert is_virtual_or_tether_nic(name) is True

    physical_names = ["eth0", "enp3s0", "wlan0", "Ethernet 1", "Wi-Fi"]
    for name in physical_names:
        assert is_virtual_or_tether_nic(name) is False

    filtered = filter_nics(virtual_names + physical_names)
    assert set(filtered) == set(physical_names)


def test_norm_list_sorting_and_deduplication():
    raw = ["GPU-B", "  GPU-A ", "GPU-B", "none", "", "0000"]
    result = norm_list(raw)
    assert result == ["gpu-a", "gpu-b"]


def test_fingerprint_deterministic_and_order_independent():
    ev1 = {
        "machine_uuid": "4C4C4544-0051-5410-8037-B3C04F343832",
        "bios_serial": "8QGT482",
        "motherboard_serial": "/8QGT482/CN1296377H0099/",
        "cpu": "Intel(R) Core(TM) i7-7600U CPU @ 2.80GHz",
        "gpus": ["NVIDIA GeForce RTX 3080", "Intel UHD Graphics 630"],
        "disks": ["NVMe Samsung SSD 970", "WDC WD10EZEX"],
        "nics": ["eth0:00:11:22:33:44:55", "wlan0:aa:bb:cc:dd:ee:ff"],
    }
    # ev2 has mixed case, shuffled list order, extra whitespace, and ignored virtual nics
    ev2 = {
        "machine_uuid": "  4c4c4544-0051-5410-8037-b3c04f343832  ",
        "bios_serial": "8qgt482",
        "motherboard_serial": " /8QGT482/CN1296377H0099/ ",
        "cpu": "intel(r)   core(tm) i7-7600u   cpu @ 2.80ghz",
        "gpus": ["Intel UHD Graphics 630", "NVIDIA GeForce RTX 3080"],
        "disks": ["WDC WD10EZEX", "NVMe Samsung SSD 970"],
        "nics": ["wlan0:aa:bb:cc:dd:ee:ff", "eth0:00:11:22:33:44:55", "docker0:02:42:ac:11:00:02"],
    }
    fp1 = compute_fingerprint(ev1)
    fp2 = compute_fingerprint(ev2)
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_fingerprint_excludes_volatile_fields():
    base_ev = {
        "machine_uuid": "4C4C4544-0051-5410-8037-B3C04F343832",
        "bios_serial": "8QGT482",
        "motherboard_serial": "CN1296377H0099",
        "cpu": "Intel Core i7",
    }
    with_volatile = dict(base_ev)
    with_volatile.update({
        "ip_address": "192.168.1.50",
        "hostname": "lab-pc-01",
        "free_space_bytes": 1024000,
        "uptime": 99999,
        "temperature": 55.2,
        "current_user": "alice",
    })
    assert compute_fingerprint(base_ev) == compute_fingerprint(with_volatile)


def test_field_hash_hmac():
    salt1 = b"deployment-salt-secret-alpha"
    salt2 = b"deployment-salt-secret-beta"
    val = "8QGT482"

    h1 = field_hash(salt1, val)
    h2 = field_hash(salt1, "8qgt482")  # case normalized
    h3 = field_hash(salt2, val)

    assert h1 is not None
    assert h1 == h2
    assert h1 != h3
    assert field_hash(salt1, None) is None
    assert field_hash(salt1, "none") is None


def test_evidence_dataclass_anchors():
    ev = IdentityEvidence(
        machine_uuid="4C4C4544-0051-5410-8037-B3C04F343832",
        bios_serial="To be filled by O.E.M.",  # placeholder -> should be ignored
        motherboard_serial="MB-999999",
        tpm_identity=None,
    )
    anchors = ev.strong_anchors()
    assert anchors == {"machine_uuid", "motherboard_serial"}
