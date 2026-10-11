"""GPU model collector with graceful degradation."""
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


def collect_gpus() -> list[str]:
    """Collect GPU model names across platforms."""
    gpus: list[str] = []

    if sys.platform == "win32":
        out = _run_cmd([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name }",
        ])
        if out:
            for line in out.splitlines():
                s = line.strip()
                if s:
                    gpus.append(s)
        return sorted(set(gpus))

    # Try nvidia-smi
    out = _run_cmd(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
    if out:
        for line in out.splitlines():
            s = line.strip()
            if s:
                gpus.append(s)
        if gpus:
            return sorted(set(gpus))

    # Try lspci
    out = _run_cmd(["lspci"])
    if out:
        for line in out.splitlines():
            lower = line.lower()
            if "vga compatible controller" in lower or "3d controller" in lower:
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    gpus.append(parts[2].strip())
        if gpus:
            return sorted(set(gpus))

    # Fallback to /sys/class/drm
    try:
        drm_path = Path("/sys/class/drm")
        if drm_path.is_dir():
            for p in drm_path.iterdir():
                if p.name.startswith("card") and "-" not in p.name:
                    gpus.append(p.name)
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("Failed reading /sys/class/drm: %s", exc)

    return sorted(set(gpus))
