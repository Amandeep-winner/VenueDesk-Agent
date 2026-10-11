"""Process list collector with graceful degradation."""
import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


def collect_processes(limit: int = 100) -> list[dict[str, Any]]:
    """Collect summary of running processes safely."""
    processes: list[dict[str, Any]] = []
    if not psutil:
        return processes

    try:
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                processes.append({
                    "pid": info.get("pid"),
                    "name": info.get("name") or "unknown",
                    "username": info.get("username"),
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "memory_percent": info.get("memory_percent") or 0.0,
                })
                if len(processes) >= limit:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
    except (OSError, AttributeError) as exc:
        logger.debug("Failed collecting process list via psutil: %s", exc)

    return processes
