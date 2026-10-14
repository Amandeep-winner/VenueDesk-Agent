"""Agent heartbeat dispatcher and background loop."""

import logging
import time
from typing import Any

from agent.communication.client import AuthenticatedClient

logger = logging.getLogger(__name__)


def send_heartbeat(client: AuthenticatedClient) -> dict[str, Any]:
    """Send a lightweight, device-signed heartbeat to the control plane."""
    now_ts = int(time.time())
    queue_depth = 0
    dropped_events = 0
    try:
        from pathlib import Path

        from agent.storage.outbox import Outbox

        outbox_path = Path(client.config.state_dir) / "outbox.db"
        if outbox_path.exists():
            outbox = Outbox(outbox_path)
            queue_depth = outbox.count()
            dropped_events = getattr(outbox, "dropped_events_count", 0)
    except (OSError, RuntimeError) as exc:
        logger.debug("Could not inspect outbox health metrics: %s", exc)

    last_error_code = client.db.get_state("last_error_code") or ""

    payload = {
        "device_id": client.id_store.device_id,
        "timestamp": now_ts,
        "agent_version": getattr(client.config, "agent_version", "0.1.0"),
        "agent_instance_id": client.id_store.agent_instance_id,
        "os_installation_id": client.id_store.os_installation_id,
        "status": "ACTIVE",
        "queue_depth": queue_depth,
        "dropped_events": dropped_events,
        "last_error_code": last_error_code,
    }

    resp = client.post("/api/v1/agents/heartbeat", json_data=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"Heartbeat failed ({resp.status_code}): {resp.text}")

    data = resp.json()
    client.db.set_state("last_heartbeat", str(now_ts))
    logger.debug("Heartbeat acknowledged: server_time=%s", data.get("server_time"))
    return data
