"""Storage and disk collector with graceful degradation."""
import json
import logging
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


def collect_disks() -> list[str]:
    """Collect unique disk serials/models across platforms."""
    disks: list[str] = []

    if sys.platform == "win32":
        out = _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_DiskDrive | ForEach-Object { $_.SerialNumber }",
        ])
        if out:
            for line in out.splitlines():
                s = line.strip()
                if s:
                    disks.append(s)
        return sorted(set(disks))

    # Linux: try lsblk -J -o NAME,SERIAL,MODEL
    out = _run_cmd(["lsblk", "-J", "-o", "NAME,SERIAL,MODEL"])
    if out:
        try:
            data = json.loads(out)
            for dev in data.get("blockdevices", []):
                ser = dev.get("serial") or dev.get("model")
                if ser:
                    disks.append(str(ser).strip())
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.debug("Failed parsing lsblk output: %s", exc)

    # Fallback Linux /sys/block
    try:
        sys_block = Path("/sys/block")
        if sys_block.is_dir():
            for d in sys_block.iterdir():
                if d.name.startswith(("loop", "ram")):
                    continue
                ser_file = d / "device" / "serial"
                if ser_file.is_file():
                    val = ser_file.read_text().strip()
                    if val:
                        disks.append(val)
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("Failed reading /sys/block: %s", exc)

    return sorted(set(disks))
