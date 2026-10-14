"""System services collector with graceful degradation."""

import logging
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


def _run_cmd(cmd: list[str]) -> str | None:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("Subprocess command %s failed: %s", cmd, exc)
    return None


def collect_services() -> list[dict[str, Any]]:
    """Collect system services status across Linux and Windows."""
    services: list[dict[str, Any]] = []

    if sys.platform == "win32":
        # First try psutil Windows service API if available
        if psutil and hasattr(psutil, "win_service_iter"):
            try:
                for s in psutil.win_service_iter():
                    try:
                        d = s.as_dict()
                        services.append(
                            {
                                "name": d.get("name", "unknown"),
                                "display_name": d.get("display_name"),
                                "status": d.get("status"),
                                "start_type": d.get("start_type"),
                            }
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        continue
                if services:
                    return services
            except (AttributeError, OSError) as exc:
                logger.debug("psutil.win_service_iter failed: %s", exc)

        # Fallback to PowerShell
        out = _run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Service | Select-Object -Property Name, Status, StartType | ConvertTo-Json -Compress",
            ]
        )
        if out:
            import json

            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    services.append(
                        {
                            "name": item.get("Name", "unknown"),
                            "display_name": item.get("Name"),
                            "status": str(item.get("Status")),
                            "start_type": str(item.get("StartType")),
                        }
                    )
                return services
            except (json.JSONDecodeError, TypeError) as exc:
                logger.debug("Failed parsing Get-Service JSON: %s", exc)
        return services

    # Linux: try systemctl list-units --type=service
    out = _run_cmd(["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"])
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                svc_name = parts[0]
                status = parts[3]
                services.append(
                    {
                        "name": svc_name,
                        "display_name": svc_name,
                        "status": status,
                        "start_type": parts[2] if len(parts) > 2 else "unknown",
                    }
                )
    return services
