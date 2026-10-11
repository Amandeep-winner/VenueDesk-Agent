"""System and OS collector with graceful degradation."""
import hashlib
import logging
import platform
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


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
