"""Telemetry metric sample collector with graceful degradation."""
import logging
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


def collect_telemetry_sample() -> dict[str, Any]:
    """Collect current endpoint telemetry sample."""
    now = datetime.now(UTC)
    now_ts = now.isoformat()

    cpu_pct = 0.0
    mem_pct = 0.0
    disk_pct = 0.0
    net_rx = 0
    net_tx = 0
    uptime_sec = 0.0
    load_avg = None

    if psutil:
        try:
            cpu_pct = float(psutil.cpu_percent(interval=None))
        except (AttributeError, OSError) as exc:
            logger.debug("Failed collecting cpu_percent: %s", exc)

        try:
            mem_pct = float(psutil.virtual_memory().percent)
        except (AttributeError, OSError) as exc:
            logger.debug("Failed collecting memory_percent: %s", exc)

        try:
            root_path = "C:\\" if sys.platform == "win32" else "/"
            disk_pct = float(psutil.disk_usage(root_path).percent)
        except (AttributeError, OSError) as exc:
            logger.debug("Failed collecting disk_percent: %s", exc)

        try:
            net_io = psutil.net_io_counters()
            if net_io:
                net_rx = int(net_io.bytes_recv)
                net_tx = int(net_io.bytes_sent)
        except (AttributeError, OSError) as exc:
            logger.debug("Failed collecting net_io_counters: %s", exc)

        try:
            boot_time = psutil.boot_time()
            uptime_sec = max(0.0, float(time.time() - boot_time))
        except (AttributeError, OSError) as exc:
            logger.debug("Failed collecting boot_time: %s", exc)

    if hasattr(os, "getloadavg"):
        try:
            load_avg = float(os.getloadavg()[0])
        except (OSError, IndexError):
            load_avg = None

    return {
        "timestamp": now_ts,
        "cpu_percent": cpu_pct,
        "memory_percent": mem_pct,
        "disk_percent": disk_pct,
        "network_rx": net_rx,
        "network_tx": net_tx,
        "uptime": uptime_sec,
        "load_average": load_avg,
        "gpu_percent": None,
        "gpu_mem_percent": None,
        "temperature_c": None,
    }
