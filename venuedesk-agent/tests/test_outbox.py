"""Comprehensive unit tests for agent offline outbox queue."""
import time
from unittest.mock import MagicMock

from agent.storage.outbox import (
    PRIORITY_IDENTITY_EVENT,
    PRIORITY_INVENTORY,
    PRIORITY_TELEMETRY,
    Outbox,
)


def test_outbox_persistence_across_restarts(tmp_path):
    """Verify outbox items persist across class reinstantiation."""
    db_file = tmp_path / "test_outbox.db"
    box1 = Outbox(db_file, max_items=100)
    box1.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"fingerprint": "abc12345"})
    box1.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "host-1"})

    assert box1.count() == 2

    # Re-open with new Outbox instance
    box2 = Outbox(db_file, max_items=100)
    assert box2.count() == 2
    items = box2.peek()
    assert len(items) == 2
    assert items[0].topic == "identity"
    assert items[0].priority == 0
    assert items[1].topic == "inventory"
    assert items[1].priority == 1


def test_outbox_strict_priority_ordering(tmp_path):
    """Verify items are peeked and flushed in strict priority order (0, 1, 2)."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=100)

    # Enqueue in reverse priority order
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 50})
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "host-1"})
    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"ev": "uuid-1"})

    items = box.peek()
    assert len(items) == 3
    assert items[0].priority == PRIORITY_IDENTITY_EVENT
    assert items[0].topic == "identity"
    assert items[1].priority == PRIORITY_INVENTORY
    assert items[1].topic == "inventory"
    assert items[2].priority == PRIORITY_TELEMETRY
    assert items[2].topic == "telemetry"


def test_outbox_ttl_expiration(tmp_path):
    """Verify items older than TTL hours are purged."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=100, ttl_hours=1)

    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample": 1})
    assert box.count() == 1

    # Artificially age the item past 1 hour (3601 seconds ago)
    with box._get_connection() as conn:
        conn.execute("UPDATE outbox SET created_at = ?", (time.time() - 3605,))
        conn.commit()

    deleted = box.purge_expired()
    assert deleted == 1
    assert box.count() == 0


def test_outbox_pressure_sheds_lowest_priority_first(tmp_path):
    """Verify buffer pressure sheds telemetry (prio 2) first, never dropping priority 0."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=3)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"device": "d1"})  # prio 0
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"host": "h1"})        # prio 1
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 10})           # prio 2

    assert box.count() == 3

    # Adding a 4th item under max_items=3 should drop the telemetry item (prio 2)
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 20})
    assert box.count() == 3

    items = box.peek()
    topics = [item.topic for item in items]
    assert "identity" in topics
    assert "inventory" in topics
    assert items[2].payload["cpu"] == 20  # The newer telemetry item replaced the older one


def test_outbox_pressure_never_drops_priority_zero(tmp_path):
    """Verify priority 0 items are never shed under buffer pressure."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=2)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"id": 1})
    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"id": 2})
    assert box.count() == 2

    # Attempting to enqueue telemetry when queue is full of priority 0 items
    res = box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu": 99})
    assert res is None  # Enqueue rejected without dropping priority 0
    assert box.count() == 2

    items = box.peek()
    assert all(item.priority == PRIORITY_IDENTITY_EVENT for item in items)


def test_outbox_flush_ordered_and_batches_telemetry(tmp_path):
    """Verify flush delivers priority 0 before 1 before 2, and batches telemetry samples."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=100)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"device": "d1"})
    box.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "h1"})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu_percent": 12.0})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu_percent": 15.0})

    call_log = []

    mock_client = MagicMock()

    def mock_post(url, json_data=None):
        call_log.append((url, json_data))
        resp = MagicMock()
        resp.status_code = 200
        return resp

    mock_client.post.side_effect = mock_post

    flushed = box.flush(mock_client)
    assert flushed == 4
    assert box.count() == 0

    # Verify call sequence
    assert call_log[0][0] == "/api/v1/agents/identity"
    assert call_log[1][0] == "/api/v1/agents/inventory"
    assert call_log[2][0] == "/api/v1/agents/telemetry"
    # Batched telemetry samples into single call
    telemetry_payload = call_log[2][1]
    assert len(telemetry_payload["samples"]) == 2
    assert telemetry_payload["samples"][0]["cpu_percent"] == 12.0
    assert telemetry_payload["samples"][1]["cpu_percent"] == 15.0


def test_outbox_flush_aborts_on_network_failure(tmp_path):
    """Verify flush halts when connection fails, preserving remaining items."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=100)

    box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"device": "d1"})
    box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"cpu_percent": 10.0})

    mock_client = MagicMock()
    mock_client.post.side_effect = ConnectionError("Server unavailable")

    flushed = box.flush(mock_client)
    assert flushed == 0
    # Items must remain in outbox
    assert box.count() == 2


def test_simulate_server_down_two_minutes_queue_drains_no_loss_priority_zero(tmp_path):
    """Exit criteria test: simulate server down 2 minutes -> agent queues -> server up -> queue drains."""
    db_file = tmp_path / "test_outbox.db"
    box = Outbox(db_file, max_items=50)

    # Agent queues priority 0, 1, and 2 items while offline
    p0_ids = []
    for i in range(3):
        id_ = box.enqueue(PRIORITY_IDENTITY_EVENT, "identity", {"event_seq": i, "anchor": f"mac-{i}"})
        p0_ids.append(id_)

    box.enqueue(PRIORITY_INVENTORY, "inventory", {"hostname": "lab-pc-10"})

    for i in range(10):
        box.enqueue(PRIORITY_TELEMETRY, "telemetry", {"sample_seq": i, "cpu_percent": 20.0 + i})

    assert box.count() == 14

    mock_client = MagicMock()
    server_online = False
    delivered_topics = []

    def handle_post(url, json_data=None):
        if not server_online:
            raise ConnectionError("Server down (503 Service Unavailable)")
        delivered_topics.append((url, json_data))
        resp = MagicMock()
        resp.status_code = 200
        return resp

    mock_client.post.side_effect = handle_post

    # 1. Attempt flush while server is down -> 0 flushed, nothing lost
    flushed = box.flush(mock_client)
    assert flushed == 0
    assert box.count() == 14

    # 2. Server comes up after 2 minutes downtime
    server_online = True
    flushed_after = box.flush(mock_client)
    assert flushed_after == 14
    assert box.count() == 0

    # Ensure all 3 priority 0 items were delivered first
    p0_delivered = [item for item in delivered_topics if item[0] == "/api/v1/agents/identity"]
    assert len(p0_delivered) == 3

