"""System and OS collector with graceful degradation."""
import hashlib
import logging
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

from agent.identity.fingerprint import is_virtual_or_tether_nic

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


def _run_cmd(cmd: list[str]) -> str | None:
    """Run command safely without shell, returning stripped stdout or None."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("Subprocess command %s failed: %s", cmd, exc)
    return None


def collect_machine_uuid() -> str | None:
    """Collect hardware/chassis machine UUID across Linux and Windows."""
    if sys.platform == "win32":
        out = _run_cmd(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"])
        if out:
            return out
    else:
        for p in ["/sys/class/dmi/id/product_uuid", "/sys/devices/virtual/dmi/id/product_uuid"]:
            try:
                path = Path(p)
                if path.is_file():
                    val = path.read_text().strip()
                    if val:
                        return val
            except (OSError, UnicodeDecodeError) as exc:
                logger.debug("Failed to read machine UUID from %s: %s", p, exc)
    return None


def collect_os_machine_id() -> str | None:
    """Collect OS installation machine ID (e.g. /etc/machine-id or Windows Cryptography MachineGuid)."""
    if sys.platform == "win32":
        out = _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid",
        ])
        if out:
            return out
    else:
        for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            try:
                path = Path(p)
                if path.is_file():
                    val = path.read_text().strip()
                    if val:
                        return val
            except (OSError, UnicodeDecodeError) as exc:
                logger.debug("Failed to read OS machine ID from %s: %s", p, exc)
    return None


def collect_os_info() -> dict[str, str]:
    """Collect OS family, name, version, architecture, and machine_id_hash."""
    sys_name = platform.system().upper()
    family = "WINDOWS" if sys_name == "WINDOWS" else ("LINUX" if sys_name == "LINUX" else "OTHER")
    os_name = platform.system()
    os_version = platform.release()
    arch = platform.machine()

    machine_id = collect_os_machine_id() or f"{platform.node()}-{platform.platform()}"
    machine_id_hash = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()

    return {
        "family": family,
        "name": os_name,
        "version": os_version,
        "architecture": arch,
        "os_machine_id_hash": machine_id_hash,
    }


def collect_hostname() -> str:
    """Collect hostname of current endpoint."""
    try:
        return socket.gethostname()
    except (OSError, AttributeError):
        return platform.node() or "unknown"


def collect_os_summary() -> str:
    """Collect descriptive summary of running OS."""
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def collect_cpu_cores() -> int | None:
    """Collect logical CPU core count."""
    if psutil:
        try:
            return psutil.cpu_count(logical=True)
        except (AttributeError, OSError):
            pass
    return os.cpu_count()


def collect_ram_total_mb() -> int | None:
    """Collect total system RAM in megabytes."""
    if psutil:
        try:
            vm = psutil.virtual_memory()
            return int(vm.total // (1024 * 1024))
        except (AttributeError, OSError) as exc:
            logger.debug("psutil.virtual_memory failed: %s", exc)

    if sys.platform == "win32":
        out = _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)",
        ])
        if out:
            try:
                return int(out.strip())
            except ValueError:
                pass
    elif sys.platform.startswith("linux"):
        try:
            meminfo = Path("/proc/meminfo")
            if meminfo.is_file():
                for line in meminfo.read_text().splitlines():
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb // 1024
        except (OSError, ValueError) as exc:
            logger.debug("Failed reading /proc/meminfo: %s", exc)
    return None


def collect_bios_version() -> str | None:
    """Collect BIOS firmware version string."""
    if sys.platform == "win32":
        return _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion",
        ])
    for p in ["/sys/class/dmi/id/bios_version", "/sys/devices/virtual/dmi/id/bios_version"]:
        try:
            path = Path(p)
            if path.is_file():
                val = path.read_text().strip()
                if val:
                    return val
        except (OSError, UnicodeDecodeError):
            pass
    return None


def collect_tpm_present() -> bool:
    """Determine whether a hardware TPM module is present."""
    from agent.collectors.hardware import collect_tpm_identity
    return bool(collect_tpm_identity())


def collect_ip_addresses() -> list[str]:
    """Collect non-loopback IPv4/IPv6 addresses."""
    ips: set[str] = set()
    if psutil:
        try:
            addrs = psutil.net_if_addrs()
            for iface_name, snic_list in addrs.items():
                if is_virtual_or_tether_nic(iface_name):
                    continue
                for snic in snic_list:
                    if snic.family in (socket.AF_INET, getattr(socket, "AF_INET6", -1)):
                        ip = snic.address.split("%")[0].strip()
                        if ip and not ip.startswith("127.") and ip != "::1":
                            ips.add(ip)
        except (OSError, AttributeError) as exc:
            logger.debug("psutil.net_if_addrs failed: %s", exc)

    if not ips:
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
            if host_ip and not host_ip.startswith("127."):
                ips.add(host_ip)
        except (socket.gaierror, OSError):
            pass

    return sorted(ips)


def collect_mac_addresses() -> list[str]:
    """Collect MAC addresses of physical adapters."""
    from agent.collectors.network import collect_nics
    nics = collect_nics()
    macs: set[str] = set()
    for nic in nics:
        if ":" in nic:
            # nic is in format '{iface}:{mac}'
            parts = nic.split(":", 1)
            macs.add(parts[1].lower())
        else:
            macs.add(nic.lower())
    return sorted(macs)
