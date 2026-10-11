"""Hardware component collectors (BIOS, Motherboard, CPU, TPM) with graceful degradation."""
import logging
import platform
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _run_cmd(cmd: list[str]) -> str | None:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("Subprocess command %s failed: %s", cmd, exc)
    return None


def collect_bios_serial() -> str | None:
    """Collect BIOS serial number across platforms."""
    if sys.platform == "win32":
        return _run_cmd(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_BIOS).SerialNumber"])
    for p in ["/sys/class/dmi/id/bios_serial", "/sys/class/dmi/id/product_serial"]:
        try:
            path = Path(p)
            if path.is_file():
                val = path.read_text().strip()
                if val:
                    return val
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed reading BIOS serial from %s: %s", p, exc)
    return None


def collect_motherboard_serial() -> str | None:
    """Collect motherboard / baseboard serial number across platforms."""
    if sys.platform == "win32":
        return _run_cmd(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_BaseBoard).SerialNumber"])
    for p in ["/sys/class/dmi/id/board_serial", "/sys/devices/virtual/dmi/id/board_serial"]:
        try:
            path = Path(p)
            if path.is_file():
                val = path.read_text().strip()
                if val:
                    return val
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed reading motherboard serial from %s: %s", p, exc)
    return None


def collect_cpu_model() -> str | None:
    """Collect CPU model description."""
    if sys.platform == "win32":
        out = _run_cmd(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"])
        if out:
            return out.splitlines()[0].strip() if out.splitlines() else out
    try:
        cpu = platform.processor()
        if cpu and cpu.strip():
            return cpu.strip()
    except (OSError, ValueError) as exc:
        logger.debug("platform.processor() failed: %s", exc)

    # Linux fallback: read /proc/cpuinfo model name
    try:
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            for line in cpuinfo.read_text().splitlines():
                if "model name" in line:
                    return line.split(":", 1)[1].strip()
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("Failed reading /proc/cpuinfo: %s", exc)
    return None


def collect_tpm_identity() -> str | None:
    """Collect TPM endorsement or version identifier if present."""
    if sys.platform == "win32":
        out = _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance -Namespace ROOT/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm).ManufacturerId",
        ])
        if out:
            return out
    else:
        for p in ["/sys/class/tpm/tpm0/device/description", "/sys/class/tpm/tpm0/id"]:
            try:
                path = Path(p)
                if path.is_file():
                    val = path.read_text().strip()
                    if val:
                        return val
            except (OSError, UnicodeDecodeError) as exc:
                logger.debug("Failed reading TPM identity from %s: %s", p, exc)
    return None
